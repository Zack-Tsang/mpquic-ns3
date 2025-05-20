/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          Wenjun Yang <wenjunyang@uvic.ca>
 *          Shengjie Shu <shengjies@uvic.ca>
 *
 */
/*
#define NS_LOG_APPEND_CONTEXT \
  if (m_node and m_connectionId and (m_streamId >= 0)) { std::clog << " [node " << m_node->GetId () << " socket " << m_connectionId << " stream " << m_streamId << " " << StreamDirectionTypeToString () << "] "; }
*/

#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "ns3/simulation-singleton.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/trace-source-accessor.h"
#include "quic-stream-base.h"
#include "quic-header.h"
#include "quic-transport-parameters.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicStreamBase");

NS_OBJECT_ENSURE_REGISTERED (QuicStreamBase);

// 用于注册QuicStreamBase类的类型信息（Type Information）到 NS-3 的类型系统中, zhiy zeng
TypeId
QuicStreamBase::GetTypeId (void)
{
  // 创建一个名为 tid 的静态 TypeId 实例，关联类名 ns3::QuicStreamBase
  static TypeId tid = TypeId ("ns3::QuicStreamBase")
    .SetParent<QuicStream> () // 声明 QuicStreamBase 是 QuicStream 的子类，继承其父类的属性和方法
    .SetGroupName ("Internet") // 将类归属到 Internet 模块组中，方便 NS-3 的模块管理和文档生成
    .AddConstructor<QuicStreamBase> () // 注册类的默认构造函数，允许 NS-3 通过反射机制创建该类的实例
    // 添加发送缓冲区大小属性
    .AddAttribute ("StreamSndBufSize", // 属性名称
                   "QuicStreamBase maximum transmit buffer size (bytes)", // 描述
                   UintegerValue (131072), // 默认值: 128 KB
                   // 访问器: MakeUintegerAccessor关联属性到类成员变量m_streamTxBufferSize, 用于读写操作
                   MakeUintegerAccessor (&QuicStreamBase::m_streamTxBufferSize), 
                   // 校验器: 确保属性值为非负整数
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("StreamRcvBufSize",
                   "QuicStreamBase maximum receive buffer size (bytes)",
                   UintegerValue (131072), // 128k
                   MakeUintegerAccessor (&QuicStreamBase::m_streamRxBufferSize),
                   MakeUintegerChecker<uint32_t> ())
    // 添加MAX_DATA 帧间隔
    .AddAttribute ("MaxDataInterval",
                   "Interval between MAX_DATA frames",
                   // 配置发送 MAX_DATA 帧的时间间隔, 表示间隔对应 10 个数据包的发送时间
                   UintegerValue (15000),                 // 10 packets
                   MakeUintegerAccessor (&QuicStreamBase::m_maxDataInterval),
                   MakeUintegerChecker<uint32_t> ())
    // 注册一个追踪源（Trace Source），用于监控接收缓冲区的状态变化
    .AddTraceSource ("RxBufferTrace",
                     "The QUIC connection's congestion window",
                     MakeTraceSourceAccessor (&QuicStreamBase::m_rxbufTrace),
                     "ns3::TracedValueCallback::Uint32")
  ;
  return tid;
}

// 获取QuicStreamBase类的类型信息, zhiy zeng
TypeId
QuicStreamBase::GetInstanceTypeId () const
{
  return QuicStreamBase::GetTypeId ();
}

// QuicStreamBase类的构造函数实现, 用于初始化 QUIC 流的基础状态和成员变量
// zhiy zeng
QuicStreamBase::QuicStreamBase (void) 
  : QuicStream (), // 父类初始化: 调用基类QuicStream的构造函数
  m_streamType (NONE), // 流类型
  m_streamDirectionType (UNKNOWN), // 流方向
  m_streamStateSend (IDLE), // 流发送状态
  m_streamStateRecv (IDLE), // 流接收状态
  m_node (0), // 所属节点指针
  m_connectionId (0), // QUIC连接ID
  m_streamId (0), // 流ID
  m_quicl5 (0), // L5协议层指针 (处理应用层数据)
  m_maxStreamData (0), // 流级最大数据量 (接收方通告)
  m_maxAdvertisedData (0), // 已通告的最大接收数据量
  m_sentSize (0), // 已发送数据量
  m_recvSize (0), // 已接收数据量
  m_fin (false) // FIN标志 (是否发送结束)
{
  NS_LOG_FUNCTION (this);
  // 创建接收和发送缓冲区对象
  m_rxBuffer = CreateObject<QuicStreamRxBuffer> (); // 接收缓冲区: 管理接收到的、但尚未被应用层读取的数据
  m_txBuffer = CreateObject<QuicStreamTxBuffer> (); // 发送缓冲区: 存储待发送的数据, 支持重传和有序发送
  // 追踪系统绑定: 将缓冲区状态变化与回调函数关联, 实现状态追踪
  m_rxBuffer->TraceConnectWithoutContext ("RxBuffer",MakeCallback (&QuicStreamBase::UpdateRxBuf, this));
}

//  QuicStreamBase 类的析构函数实现, 其作用是释放类实例在生命周期内分配的资源, 
// 并执行必要的清理操作, zhiy zeng
QuicStreamBase::~QuicStreamBase (void)
{
  NS_LOG_FUNCTION (this);
}

// 设置 QUIC L5 协议层（QuicL5Protocol）的方法 SetQuicL5，用于关联流与上层协议处理逻辑
// QuicL5Protocol 是 NS-3 中模拟 QUIC 协议第五层（应用层适配层）的组件，
// 负责处理流与应用层之间的数据交互, zhiy zeng
void
QuicStreamBase::SetQuicL5 (Ptr<QuicL5Protocol> quicl5)
{
  NS_LOG_FUNCTION (this); // 记录函数调用日志
  m_quicl5 = quicl5; // 保存 L5 协议层指针
  SetStreamRcvBufSize (m_streamRxBufferSize); // 配置接收缓冲区大小
  SetStreamSndBufSize (m_streamTxBufferSize); // 配置发送缓冲区大小
}

// 实现数据发送功能的 Send 方法，用于将应用层数据封装为 QUIC 帧并发送, 
// 返回发送的字节数, zhiy zeng
int
QuicStreamBase::Send (Ptr<Packet> frame)
{
  NS_LOG_FUNCTION (this);
  // 流状态检查与更新: 若流当前状态为 IDLE (空闲) 且方向为单向发送 (SENDER) 或双向 (BIDIRECTIONAL), 
  // 则将发送状态更新为 OPEN (打开), zhiy zeng
  SetStreamStateSendIf (m_streamStateSend == IDLE and (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL), OPEN);

  // 可发送状态判断
  if (m_streamStateSend == OPEN or m_streamStateSend == SEND)
    {
      int sent = AppendingTx (frame); // 将数据帧添加到发送缓冲区, 返回实际发送的字节数


      NS_LOG_LOGIC ("Sending packets in stream. TxBufSize = " << m_txBuffer->AppSize () << " AvailableWindow = " << AvailableWindow () << " state " << QuicStreamStateName[m_streamStateSend]);
      // AvailableWindow() 函数返回当前流的可用窗口大小
      if ((m_streamStateSend == OPEN or m_streamStateSend == SEND) and AvailableWindow () > 0)
        {
          // 若可用窗口大于 0 且发送事件未运行, 立即调度 SendPendingData 事件
          if (!m_streamSendPendingDataEvent.IsRunning ())
            {
              // std::cout<<"quic-stream-base.cc ----tst"<<std::endl;
              //m_streamSendPendingDataEvent = Simulator::Schedule (TimeStep (1), &QuicStreamBase::SendPendingData, this);
              // if (m_quicl5->vnReceived)
              // {
                // std::cout<<"****m_quicl5->vnReceived = 1";
              //   SendPendingData();
              //   m_quicl5->vnReceived = 0;

              // }else{
                // 调用 SendPendingData 函数, 发送发送缓冲区中的数据
                m_streamSendPendingDataEvent = Simulator::ScheduleNow (&QuicStreamBase::SendPendingData, this);
                // std::cout<<"quic-stream-base.cc ----sendpendingdata"<<std::endl;
              // }
            }
        }
      return sent;
    }
  else // 状态不合法时: 触发 NS_ABORT_MSG 终止程序, 提示状态错误
    {
      NS_ABORT_MSG ("Sending in state" << QuicStreamStateName[m_streamStateSend]);
      //m_errno = ERROR_NOTCONN;
      return -1;
    }
}

// 将数据帧追加到流的发送缓冲区中, 返回实际写入的字节数, zhiy zeng
int
QuicStreamBase::AppendingTx (Ptr<Packet> frame)
{
  NS_LOG_FUNCTION (this);

  if (!m_txBuffer->Add (frame))
    {
      NS_LOG_WARN ("Exceeding Stream Tx Buffer Size");
      //m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
      //                                     "Received RST_STREAM in Stream 0");
      //m_errno = ERROR_MSGSIZE;
      return -1;
    }
  return frame->GetSize ();
}

// 获取当前流的发送缓冲区大小, 返回值为发送缓冲区中尚未发送的数据字节数, zhiy zeng
uint32_t
QuicStreamBase::GetStreamTxAvailable () const
{
  return m_txBuffer->Available ();
}

// 发送当前流中尚未发送的数据帧并返回发送的数据帧数, zhiy zeng
uint32_t
QuicStreamBase::SendPendingData (void)
{
  NS_LOG_FUNCTION (this);

  // 如果应用层没有待发送的数据, 则直接返回, 不进行任何操作
  if (m_txBuffer->AppSize () == 0)
    {
      NS_LOG_INFO ("Nothing to send");
      return false;
    }

  uint32_t nFrameSent = 0;
  uint32_t availableWindow = AvailableWindow (); // 获取当前可用的发送窗口大小

  while (availableWindow > 0 and m_txBuffer->AppSize () > 0)
    {
//	  uint32_t availableData = m_txBuffer->Available();

//	  if(availableData < availableWindow)
//	  {
//	          NS_LOG_INFO("Ask the app for more data before trying to send");
//		  NotifySend(GetTxAvailable());
//	  }

//	  if(availableWindow < m_quicl5->GetMaxPacketSize() and availableData > availableWindow)
//	  {
//	          NS_LOG_INFO("Preventing Silly Windows Syndrome. Wait to Send.");
//		  break;
//	  }


      uint32_t s = std::min (availableWindow, (uint32_t)m_quicl5->GetMaxPacketSize ());

      NS_LOG_DEBUG ("BEFOREAvailable Window " << AvailableWindow () <<
                    "Stream RWnd " << StreamWindow () <<
                    "BytesInFlight " << m_txBuffer->BytesInFlight () << "BufferedSize " << m_txBuffer->AppSize () <<
                    "MaxPacketSize " << (uint32_t)m_quicl5->GetMaxPacketSize ());
      // 发送数据帧, 该函数会将数据帧添加到 QUIC L5 协议层的发送队列中
      // m_sentSize为帧的序号, s为最大帧数据的最大大小, 返回值为发送的字节数, 
      // 如果发送失败, 则返回 -1
      int success = SendDataFrame ((SequenceNumber32)m_sentSize, s);

      availableWindow = AvailableWindow ();

      if (success < 0)
        {
          return -1;
        }

      NS_LOG_DEBUG ("AFTERAvailable Window " << AvailableWindow () <<
                    "Stream RWnd " << StreamWindow () <<
                    "BytesInFlight " << m_txBuffer->BytesInFlight () << "BufferedSize " << m_txBuffer->AppSize () <<
                    "MaxPacketSize " << (uint32_t)m_quicl5->GetMaxPacketSize ());
      
      // 发送的数据帧数加1
      ++nFrameSent;

    }

  if (nFrameSent > 0)
    {
      NS_LOG_INFO ("SendPendingData sent " << nFrameSent << " frames");
    }
  else
    {
      NS_LOG_INFO ("SendPendingData no frames sent");
    }

  return nFrameSent;
}

// 用于发送 QUIC 流数据帧, 返回发送的字节数, zhiy zeng
uint32_t
QuicStreamBase::SendDataFrame (SequenceNumber32 seq, uint32_t maxSize)
{
  NS_LOG_FUNCTION (this);

  if (m_streamStateSend == OPEN and (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
    {
      SetStreamStateSend (SEND);
    }
  // 从发送缓冲区m_txBuffer中取出一段待发送的数据帧, 该数据帧的大小不超过 maxSize
  // 该数据帧的序列号为 seq, 该序列号是一个 SequenceNumber32 类型的对象
  Ptr<Packet> frame = m_txBuffer->NextSequence (maxSize, seq);

  bool lengthBit = true;

  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (m_streamId, (uint64_t)seq.GetValue (), frame->GetSize (), m_sentSize != 0, lengthBit, m_fin);
  // std::cout<<"size"<< frame->GetSize ()<<std::endl;
  m_sentSize += frame->GetSize ();

  frame->AddHeader (sub);
  int size = m_quicl5->Send (frame);
  if (size < 0)
    {
      frame->RemoveHeader (sub);
      m_txBuffer->Rejected (frame);
      NS_LOG_WARN ("Sending error - could not append packet to socket buffer. Putting packet back in stream buffer");
      m_sentSize -= frame->GetSize ();
    }
  else if (m_streamStateSend == SEND and m_fin and (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
    {
      SetStreamStateSend (DATA_SENT);
    }

  return size;
}

// 返回当前流 (stream) 的可用窗口大小 (用于流量控制), zhiy zeng
uint32_t
QuicStreamBase::AvailableWindow () const
{
  NS_LOG_FUNCTION (this);
  // 如果 m_streamId != 0 成立 (即不是控制流或初始流), 则调用 StreamWindow() 函数来获取当前流的接收窗口大小
  // 否则 (例如是数据流)，直接使用 m_maxStreamData 的值作为窗口大小
  uint32_t streamRWnd = (m_streamId != 0) ? StreamWindow () : m_maxStreamData;
  return streamRWnd;
}

// 返回当前流的接收窗口大小, zhiy zeng
uint32_t
QuicStreamBase::StreamWindow () const
{
  NS_LOG_FUNCTION (this);
  uint32_t inFlight = m_txBuffer->BytesInFlight ();
  // 如果当前“飞行中”的数据量已经超过最大允许的数据量, 则返回 0, 
  // 反之返回m_maxStreamData - inFlight, zhiy zeng
  return (inFlight > m_maxStreamData) ? 0 : m_maxStreamData - inFlight;
}

// 用于解析接收到的 QUIC 帧并更新流状态, zhiy zeng
int
QuicStreamBase::Recv (Ptr<Packet> frame, const QuicSubheader& sub, Address &address)
{
  NS_LOG_FUNCTION (this);

  // 根据 QUIC 子头部（QuicSubheader）识别帧类型
  uint8_t frameType = sub.GetFrameType ();

  // 状态机更新：根据帧类型和当前流状态，转移流的接收状态
  switch (frameType)
    {
    
    // RST_STREAM帧 (流重置): 处理流重置请求, 终止异常流, 释放资源
    case QuicSubheader::RST_STREAM:
      // TODO reset and close this stream
      if (m_streamId == 0)
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received RST_STREAM in Stream 0");
          return -1;
        }

      if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received RST_STREAM in send-only Stream");
          return -1;
        }

      if ((m_streamStateRecv == DATA_READ or m_streamStateRecv == RESET_READ))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Receiving RST_STREAM Frames in DATA_READ or RESET_READ Stream State");
          return -1;
        }

      if (m_fin and m_rxBuffer->GetFinalSize () != sub.GetOffset ())
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::FINAL_OFFSET_ERROR,
                                           "RST_STREAM causes final offset to change for a Stream");
          return -1;
        }
      SetStreamStateRecvIf (m_streamStateRecv == RECV or m_streamStateSend == SIZE_KNOWN or m_streamStateSend == DATA_RECVD, RESET_RECVD);

      break;
    
    // MAX_STREAM_DATA帧 (流量控制): 更新流的最大接收数据量, 该值由接收方通告
    case QuicSubheader::MAX_STREAM_DATA:
      if (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received MAX_STREAM_DATA in receive-only Stream");
          return -1;
        }
      else
        {
          SetMaxStreamData (sub.GetMaxStreamData ());
          NS_LOG_INFO ("Max stream data (flow control) - " << m_maxStreamData);
        }

      break;

    case QuicSubheader::STREAM_BLOCKED:
      // TODO block the stream
      if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STREAM_BLOCKED in send-only Stream");
          return -1;
        }

      break;

    case QuicSubheader::STOP_SENDING:
      // TODO implement a mechanism to stop sending data
      if (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STOP_SENDING in receive-only Stream");
          return -1;
        }

      break;

    case QuicSubheader::STREAM000:
    case QuicSubheader::STREAM001:
    case QuicSubheader::STREAM010:
    case QuicSubheader::STREAM011:
    case QuicSubheader::STREAM100:
    case QuicSubheader::STREAM101:
    case QuicSubheader::STREAM110:
    case QuicSubheader::STREAM111:


      if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STREAM in send-only Stream");
          return -1;
        }

      if (!(m_streamStateRecv == IDLE or m_streamStateRecv == RECV or m_streamStateRecv == SIZE_KNOWN))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STREAM in State unequal to IDLE, RECV, SIZE_KNOWN");
          return -1;
        }

      if (m_rxBuffer->Size () + sub.GetLength () > m_maxStreamData)
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
                                           "Received more data w.r.t. Max Stream Data limit");
          return -1;
        }
      SetStreamStateRecvIf (m_streamStateRecv == IDLE, RECV);

      if (m_quicl5->ContainsTransportParameters () and m_streamId == 0)
        {
          QuicTransportParameters transport;
          // std::cout<<frame->ToString()<<"\n";
          // std::cout<<m_quicl5->ContainsTransportParameters ()<<"\n";
          frame->RemoveHeader (transport);
          m_quicl5->OnReceivedTransportParameters (transport);
        }
      
      if (m_fin and sub.IsStreamFin () and m_rxBuffer->GetFinalSize () != sub.GetOffset ())
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::FINAL_OFFSET_ERROR,
                                           "STREAM causes final offset to change for a Stream");
          return -1;
        }

      m_fin = sub.IsStreamFin ();

      if (m_fin && m_streamId == 0)
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received Stream FIN in Stream 0");
          return -1;
        }
      SetStreamStateRecvIf (m_streamStateRecv == RECV and m_fin, SIZE_KNOWN);


    // temp_comment
    std::cout<< Simulator::Now ().GetSeconds () << "\t"<< m_streamId <<"\t" << m_recvSize<<"\t"<<sub.GetOffset ()<< "\t" << m_rxBuffer->Size () << "\t" <<std::endl;

    //  std::cout<< Simulator::Now ().GetSeconds () << "--///--Received a frame on stream "<< m_streamId <<" with the size " << sub.GetLength ()<<" expected offset: "<<m_recvSize<<" actual offset:"<<sub.GetOffset ()<< " Buffer Size: " << m_rxBuffer->Size ()<<std::endl;

      if (m_recvSize == sub.GetOffset ()) 
        {

          NS_LOG_INFO ("Received a frame with the correct order of size " << sub.GetLength ());
         
          m_recvSize += sub.GetLength ();

          if (m_maxAdvertisedData == 0 || m_recvSize + m_rxBuffer->Available () > m_maxAdvertisedData + m_maxDataInterval)
            {
              m_maxAdvertisedData = m_recvSize + m_rxBuffer->Available ();
              QuicSubheader sub = QuicSubheader::CreateMaxData (m_recvSize + m_rxBuffer->Available ());
              // build empty packet
              Ptr<Packet> maxStream = Create<Packet> (0);
              maxStream->AddHeader (sub);
              m_quicl5->Send (maxStream);
            }

          NS_LOG_LOGIC ("Try to Flush RxBuffer if Available - offset " << m_recvSize);
          // check if the packets in the RX buffer can be released (in order release)
          std::pair<uint64_t, uint64_t> offSetLength = m_rxBuffer->GetDeliverable (m_recvSize);
          NS_LOG_LOGIC ("Extracting " << offSetLength.second << " bytes from RxBuffer");
          if (offSetLength.second > 0)
            {
              Ptr<Packet> payload = m_rxBuffer->Extract (offSetLength.second);
              m_recvSize += offSetLength.second;
              if (payload) {
                frame->AddAtEnd (payload);
              }
            }
          NS_LOG_LOGIC ("Flushed RxBuffer - new offset " << m_recvSize << ", " << m_rxBuffer->Available () << "bytes available");
          SetStreamStateRecvIf (m_streamStateRecv == SIZE_KNOWN and m_rxBuffer->Size () == 0, DATA_RECVD);

          if (m_streamId != 0 )
            {
              if (sub.GetMaxStreamData () > 0)
                {
                  SetMaxStreamData (sub.GetMaxStreamData ());
                  NS_LOG_LOGIC ("Received window set to offset " << sub.GetMaxStreamData ());
                }
              m_quicl5->Recv (frame, address);
            }
          else
            {
              NS_LOG_INFO ("Received handshake Message in Stream 0");
            }
          SetStreamStateRecvIf (m_streamStateRecv == DATA_RECVD, DATA_READ);

        }
      else
        {
          if (m_streamId != 0 && sub.GetMaxStreamData () > 0)
            {
              SetMaxStreamData (sub.GetMaxStreamData ());
              NS_LOG_LOGIC ("Received window set to offset " << sub.GetMaxStreamData ());
            }
          NS_LOG_INFO ("Buffering unordered received frame - offset " << m_recvSize << ", frame offset " << sub.GetOffset ());
          // std::cout<<"quic-stream-base.cc  Buffering unordered received frame of size " << sub.GetLength () <<" m_recvSize: "<<m_recvSize<< ", frame offset " << sub.GetOffset ()<<std::endl;
          if (!m_rxBuffer->Add (frame, sub) && frame->GetSize () > 0)
            {
              // Insert failed: No or duplicate data, or RX buffer full
              NS_LOG_WARN ("Dropping packet as it could not be inserted in RX buffer");
              if (frame->GetSize() > m_rxBuffer->Available()) {
                  // Abort connection if indeed buffer is full
                  m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::NO_ERROR, "Aborting connection due to full RX buffer");
              }
            }
        }

      break;

    default:

      NS_ABORT_MSG ("Received Corrupted Frame");
      break;
    }

  return 0;
}

// void
// QuicStreamBase::CommandFlow (uint8_t type)
// {
//   NS_LOG_FUNCTION (this);

//   switch (type)
//     {

//     case QuicSubheader::RST_STREAM:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL), " Sending RstStream Frames in Receiver Stream");
//       NS_ABORT_MSG_IF ((m_streamStateRecv == DATA_READ or m_streamStateRecv == RESET_READ or m_streamStateRecv == RESET_SENT), " Sending RstStream Frames in " << QuicStreamStateName[m_streamStateRecv] << " State");

//       SetStreamStateSendIf (m_streamStateSend == OPEN or m_streamStateSend == SEND or m_streamStateSend == DATA_SENT, RESET_SENT);
//       //	if((m_streamStateSend = OPEN or m_streamStateSend == SEND or m_streamStateSend == DATA_SENT)){SetStreamStateSend(RESET_SENT);}

//       break;

//     case QuicSubheader::MAX_STREAM_DATA:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL), " Sending MaxStreamData Frame in Sender Stream");

//       break;

//     case QuicSubheader::STREAM_BLOCKED:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL), " Sending StreamBlocked Frame in Receiver Stream");

//       break;

//     case QuicSubheader::STOP_SENDING:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL), " Sending StopSending Frame in Sender Stream");

//       break;

//     default:
//       NS_ABORT_MSG ("Received Corrupted Command");
//       break;

//     }

// }

uint32_t
QuicStreamBase::SendMaxStreamData ()
{
  return m_recvSize + m_rxBuffer->Available ();
}

void
QuicStreamBase::SetMaxStreamData (uint32_t maxStreamData)
{
  NS_LOG_FUNCTION (this << maxStreamData);
  NS_LOG_DEBUG ("Update max stream data from " << m_maxStreamData << " to " << maxStreamData);
  m_maxStreamData = maxStreamData;
}

uint32_t
QuicStreamBase::GetMaxStreamData () const
{
  return m_maxStreamData;
}

void
QuicStreamBase::SetStreamDirectionType (const QuicStreamDirectionTypes_t& streamDirectionType)
{
  NS_LOG_FUNCTION (this);
  m_streamDirectionType = streamDirectionType;
}

QuicStream::QuicStreamDirectionTypes_t
QuicStreamBase::GetStreamDirectionType ()
{
  return m_streamDirectionType;
}

void
QuicStreamBase::SetStreamType (const QuicStreamTypes_t& streamType)
{
  NS_LOG_FUNCTION (this);
  m_streamType = streamType;
}

void
QuicStreamBase::SetStreamStateSend (const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);

  if (m_streamType == SERVER_INITIATED_BIDIRECTIONAL or m_streamType == SERVER_INITIATED_UNIDIRECTIONAL)
    {

      NS_LOG_INFO ("Server Stream " << QuicStreamStateName[m_streamStateSend] << " -> " << QuicStreamStateName[streamState] << "");

    }
  else
    {

      NS_LOG_INFO ("Client Stream " << QuicStreamStateName[m_streamStateSend] << " -> " << QuicStreamStateName[streamState] << "");

    }

  m_streamStateSend = streamState;
}

void
QuicStreamBase::SetStreamStateSendIf (bool condition, const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);
  if (condition)
    {
      SetStreamStateSend (streamState);
    }
}


void
QuicStreamBase::SetStreamStateRecv (const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);

  if (m_streamType == SERVER_INITIATED_BIDIRECTIONAL or m_streamType == SERVER_INITIATED_UNIDIRECTIONAL)
    {

      NS_LOG_INFO ("Server Stream " << QuicStreamStateName[m_streamStateRecv] << " -> " << QuicStreamStateName[streamState] << "");

    }
  else
    {

      NS_LOG_INFO ("Client Stream " << QuicStreamStateName[m_streamStateRecv] << " -> " << QuicStreamStateName[streamState] << "");

    }

  m_streamStateRecv = streamState;
}

void
QuicStreamBase::SetStreamStateRecvIf (bool condition, const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);
  if (condition)
    {
      SetStreamStateRecv (streamState);
    }
}

void
QuicStreamBase::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this);
  m_node = node;
}

void
QuicStreamBase::SetStreamId (uint64_t streamId)
{
  NS_LOG_FUNCTION (this);
  m_streamId = streamId;

  uint64_t mask = 0x00000003;

  switch (m_streamId & mask)
    {

    case 0:
      SetStreamType (QuicStream::CLIENT_INITIATED_BIDIRECTIONAL);
      break;
    case 1:
      SetStreamType (QuicStream::SERVER_INITIATED_BIDIRECTIONAL);
      break;
    case 2:
      SetStreamType (QuicStream::CLIENT_INITIATED_UNIDIRECTIONAL);
      break;
    case 3:
      SetStreamType (QuicStream::SERVER_INITIATED_UNIDIRECTIONAL);
      break;
    }

}

uint64_t
QuicStreamBase::GetStreamId (void)
{
  return m_streamId;
}

void
QuicStreamBase::SetConnectionId (uint64_t connId)
{
  NS_LOG_FUNCTION (this << connId);
  m_connectionId = connId;
}

std::string
QuicStreamBase::StreamDirectionTypeToString () const
{
  static const char* StreamDirectionTypeNames[6] = {
    "SENDER",
    "RECEIVER",
    "BIDIRECTIONAL",
    "UNKNOWN"
  };

  std::string typeDescription = "";

  typeDescription.append (StreamDirectionTypeNames[m_streamDirectionType]);

  return typeDescription;
}

void
QuicStreamBase::SetStreamSndBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_streamTxBufferSize = size;
  m_txBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicStreamBase::GetStreamSndBufSize (void) const
{
  return m_txBuffer->GetMaxBufferSize ();
}

void
QuicStreamBase::SetStreamRcvBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_streamRxBufferSize = size;
  m_rxBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicStreamBase::GetStreamRcvBufSize (void) const
{
  return m_rxBuffer->GetMaxBufferSize ();
}


void
QuicStreamBase::UpdateRxBuf (uint32_t oldValue, uint32_t newValue)
{
  m_rxbufTrace (oldValue, newValue);
}

} // namespace ns3

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
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
 *          Umberto Paro <umberto.paro@me.com>
 *          Shengjie Shu <shengjies@uvic.ca>
 */

#define __STDC_LIMIT_MACROS

#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/boolean.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/nstime.h"
#include "quic-socket.h"
#include "mp-quic-congestion-ops.h"
#include "quic-socket-base.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("MpQuicCongestionControl");

NS_OBJECT_ENSURE_REGISTERED (MpQuicCongestionOps);

/**
 * 作用：注册多路径QUIC拥塞控制算法（Multipath QUIC 
    Congestion Control） 类型信息, 为 MpQuicCongestionOps 
    类注册一个全局唯一的类型标识符
 * 返回值
    返回一个 TypeId 对象，表示该类的类型信息
 * zhiy zeng
 */
TypeId
MpQuicCongestionOps::GetTypeId (void)
{
  // 定义并初始化一个静态的 TypeId 实例, "ns3::MpQuicCongestionControl" 
  // 是该类的唯一全限定名
  static TypeId tid = TypeId ("ns3::MpQuicCongestionControl")
    .SetParent<QuicCongestionOps> () // 设置父类为 QuicCongestionOps, 
    // 可以作为 QUIC 协议栈中的一种拥塞控制算法使用
    .SetGroupName ("Internet") // 将此类归类到 "Internet" 组
    .AddConstructor<MpQuicCongestionOps> () // 添加构造函数支持
  ;
  return tid;
}

/**
 * 作用：MpQuicCongestionOps类的构造函数
 * 参数：无
 * 返回值：无
 * zhiy zeng
 */
MpQuicCongestionOps::MpQuicCongestionOps (void)
  : QuicCongestionOps ()
{
  NS_LOG_FUNCTION (this);
}

/**
 * 作用：MpQuicCongestionOps类的拷贝构造函数
  * 用于创建一个新的MpQuicCongestionOps对象，并将另一个对象的状态复制到新对象中
 * 参数：sock - 另一个MpQuicCongestionOps对象的引用
 * 返回值：无
 */
MpQuicCongestionOps::MpQuicCongestionOps (
  const MpQuicCongestionOps& sock)
  : QuicCongestionOps (sock) // 调用基类的拷贝构造函数
{
  NS_LOG_FUNCTION (this);
}

/**
 * 作用：MpQuicCongestionOps类的析构函数
 * 参数：无
 * 返回值：无
 * zhiy zeng
 */
MpQuicCongestionOps::~MpQuicCongestionOps (void)
{}

/**
 * 作用：获取当前拥塞控制算法的名称
 * 参数：无
 * 返回值：
 * 返回一个字符串，表示当前拥塞控制算法的名称
 * zhiy zeng
 */
std::string
MpQuicCongestionOps::GetName () const
{
  return "MpQuicCongestionControl_OLIA";
}

/**
 * 作用：创建并返回该拥塞控制对象的一个副本；
 * 返回值：
  * 返回一个指向 TcpCongestionOps 的智能指针；
  * 实际上指向的是 MpQuicCongestionOps 类型的对象；
 * zhiy zeng
 */
Ptr<TcpCongestionOps>
MpQuicCongestionOps::Fork ()
{
  // CopyObject(...) 方法创建当前对象的深拷贝
  return CopyObject<MpQuicCongestionOps> (this);
}

// Quic DRAFT 10
/**
 * 作用：当一个数据包被发送后，更新拥塞控制相关状态；
 * 参数说明：
  * tcb: 传输控制块（Transmission Control Block），保存当前连接的状态；
  * packetNumber: 当前发送的数据包编号（QUIC 使用 32 位序列号）；
  * isAckOnly: 是否为纯 ACK 包（即不携带应用数据的包）；
 * 返回值：无；
 * zhiy zeng
 */
void
MpQuicCongestionOps::OnPacketSent (Ptr<TcpSocketState> tcb,
                                 SequenceNumber32 packetNumber,
                                 bool isAckOnly)
{
  NS_LOG_FUNCTION (this << packetNumber << isAckOnly);
  // 类型转换: 将通用的 TcpSocketState 转换为更具体的 QuicSocketState
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");
  // 更新状态:
  // 记录最近一次发送数据包的时间，用于 RTT 测量或超时判断 
  tcbd->m_timeOfLastSentPacket = Now (); 
  // 记录当前已发送的最高数据包编号，用于检测丢失或重复
  tcbd->m_highTxMark = packetNumber;
}

/**
 * 作用：处理接收的ACK帧，更新拥塞控制相关状态；
 * 参数说明：
  * tcb: 当前连接的状态块（Transmission Control Block）；
  * ack: 包含 ACK 信息的 QUIC 子头部；
  * newAcks: 新近被确认的数据包列表；
  * rs: 带宽采样结构体（未使用）；
  * alpha, sum_rate: 多路径调度算法中的权重和总速率；
 * 返回值：无；
 * zhiy zeng
 */
void
MpQuicCongestionOps::OnAckReceived (Ptr<TcpSocketState> tcb,
                                  QuicSubheader &ack,
                                  std::vector<Ptr<QuicSocketTxItem> > newAcks,
                                  const struct RateSample *rs, double alpha, double sum_rate)
{
  NS_LOG_FUNCTION (this); // 日志记录: NS-3 的标准日志宏，用于记录函数调用信息
  NS_UNUSED (rs); // 忽略 RateSample 参数（目前未使用）
  // 将 TcpSocketState 转换为 QuicSocketState 类型
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  // 如果转换失败则触发断言
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");
  // 从 ACK帧 中提取最大的已确认数据包编号
  tcbd->m_largestAckedPacket = SequenceNumber32 (ack.GetLargestAcknowledged ());
  
  // newAcks are ordered from the highest packet number to the smalles
  // newAcks 是按数据包编号降序排列的，所以 at(0) 是最高编号
  Ptr<QuicSocketTxItem> lastAcked = newAcks.at (0);

  NS_LOG_LOGIC ("Updating RTT estimate");
  // If the largest acked is newly acked, update the RTT.
  // 如果当前 ACK 的数据包编号等于当前最大已确认数据包编号
  if (lastAcked->m_packetNumber == tcbd->m_largestAckedPacket)
    {
      // 计算当前 RTT（Round Trip Time）估计值
      tcbd->m_lastRtt = Now () - lastAcked->m_lastSent;
      // 调用 UpdateRtt(...) 更新 RTT 估计值，并考虑 ACK 延迟
      UpdateRtt (tcbd, tcbd->m_lastRtt, Time (ack.GetAckDelay ()));
    }

  NS_LOG_LOGIC ("Processing acknowledged packets");
  // Process each acked packet
  // 遍历新确认的数据包列表，从后向前处理（因为是降序排列）
  for (auto it = newAcks.rbegin (); it != newAcks.rend (); ++it)
    {
      if ((*it)->m_acked)
        {
          m_inCCAvoid = false;
          // 对于每一个已经被确认的数据包，调用 OnPacketAcked(...) 进行进一步处理
          OnPacketAcked (tcb, (*it), alpha, sum_rate);
          if (m_inCCAvoid) // 如果 m_inCCAvoid 标志被设置为真（表示进入某种拥塞避免模式）
          {
            return;
          }
        }
    }
}

/**
 * 作用：根据最新的 RTT 测量值和 ACK 延迟，更新连接的 RTT 估计；
 * 参数说明：
  * tcb：指向当前连接状态的指针；
  * latestRtt：最近一次测量到的 RTT；
  * ackDelay：ACK 被延迟发送的时间（由接收端引入）；
 * 返回值：无；
 * zhiy zeng
 */
void
MpQuicCongestionOps::UpdateRtt (Ptr<TcpSocketState> tcb, Time latestRtt,
                              Time ackDelay)
{
  // 日志记录: NS-3 的标准日志宏，用于记录函数调用信息
  NS_LOG_FUNCTION (this);
  // 将通用的 TcpSocketState 转换为具体的 QuicSocketState 类型
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  // 如果转换失败则触发断言
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");

  // m_minRtt ignores ack delay.
  // 更新最小 RTT（忽略 ACK 延迟, 因为这个值可能受接收端处理延迟影响）
  tcbd->m_minRtt = std::min (tcbd->m_minRtt, latestRtt);

  NS_LOG_LOGIC ("Correct for ACK delay");
  // Adjust for ack delay if it's plausible.
  // 校正最新 RTT（考虑 ACK 延迟）
  if (latestRtt - tcbd->m_minRtt > ackDelay) 
    { // 如果 ackDelay 可能对 RTT 造成显著影响
      latestRtt -= ackDelay;
      // TODO check this condition
      // Only save into max ack delay if it's used for rtt calculation and is not ack only
//        if (!tcbd->m_sentPackets[tcbd->m_largestAckedPacket]->m_ackOnly)
//          {
//            tcbd->m_maxAckDelay = std::max (tcbd->m_maxAckDelay, ackDelay);
//          }
    }

  NS_LOG_LOGIC ("Update smoothed RTT");
  // Based on [RFC6298].
  // 更新平滑 RTT（Smoothed RTT）和 RTT 方差（RFC 6298 算法）
  if (tcbd->m_smoothedRtt == Seconds (0))
    {
      tcbd->m_smoothedRtt = latestRtt;
      tcbd->m_rttVar = latestRtt / 2;
    }
  else
    {
      Time rttVarSample = Time (
        std::abs ((tcbd->m_smoothedRtt - latestRtt).GetDouble ()));
      tcbd->m_rttVar = 3 / 4 * tcbd->m_rttVar + 1 / 4 * rttVarSample;
      tcbd->m_smoothedRtt = 7 / 8 * tcbd->m_smoothedRtt + 1 / 8 * latestRtt;
    }

}

/**
 * zhiy zeng: 多路径 QUIC 拥塞控制模块中处理单个数据包被确认的核心函数
 * 作用：当一个数据包被确认后，更新拥塞控制状态和相关计数器；
 * 参数说明：
  * tcb: 当前连接的状态块；
  * ackedPacket: 被确认的数据包对象；
  * alpha: 多路径调度算法中的权重因子；
  * sum_rate: 所有路径的总速率；
 * 返回值：无；
 */
void
MpQuicCongestionOps::OnPacketAcked (Ptr<TcpSocketState> tcb,
                                  Ptr<QuicSocketTxItem> ackedPacket, double alpha, double sum_rate)
{
  NS_LOG_FUNCTION (this);
  // 将通用的 TcpSocketState 转换为具体的 QuicSocketState
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  // 如果转换失败则触发断言
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");
  // 调用拥塞控制核心逻辑: 更新拥塞窗口
  OnPacketAckedCC (tcbd, ackedPacket, alpha, sum_rate);

  NS_LOG_LOGIC ("Handle possible RTO");
  // If a packet sent prior to RTO was acked, then the RTO  was spurious. Otherwise, inform congestion control.
  // 处理可能的虚假 RTO: 当前处于 RTO 阶段（m_rtoCount > 0）, 并且这个被确认的数据包是在 RTO 触发后发送的
  if (tcbd->m_rtoCount > 0 and ackedPacket->m_packetNumber > tcbd->m_largestSentBeforeRto)
    {
      // 调用 OnRetransmissionTimeoutVerified(...) 来通知拥塞控制模块 RTO 已验证无效
      OnRetransmissionTimeoutVerified (tcb);
    }
  // 重置超时计数器
  tcbd->m_handshakeCount = 0; // 握手阶段的超时计数
  tcbd->m_tlpCount = 0; // TLP（Tail Loss Probe）尝试次数
  tcbd->m_rtoCount = 0; // RTO（Retransmission Timeout）次数
}

/**
 * 作用：拥塞控制状态判断函数, 用于判断给定的数据包编号是否属于当前的恢复阶段；
 * 参数说明：
  * tcb: 指向当前连接的状态块；
  * packetNumber: 要检查的数据包编号；
 * 返回值：
  * 如果该数据包编号小于或等于 m_endOfRecovery，返回 true，表示该包在恢复阶段中；
  * 否则返回 false；
 * zhiy zeng 
 */
bool
MpQuicCongestionOps::InRecovery (Ptr<TcpSocketState> tcb,
                               SequenceNumber32 packetNumber)
{
  NS_LOG_FUNCTION (this << packetNumber.GetValue ());
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");
  // 检查当前数据包编号是否在恢复阶段内
  // m_endOfRecovery 是当前恢复阶段的结束数据包编号
  // 这个判断通常用于决定是否需要再次减小拥塞窗口（避免重复反应丢包）
  return packetNumber <= tcbd->m_endOfRecovery;
}

/**
 * zhiy zeng: 多路径 QUIC 拥塞控制模块中的拥塞窗口更新逻辑, 根据当前网络状态
  * （是否处于恢复阶段、慢启动或拥塞避免）来决定如何调整拥塞窗口（cWnd），从而
  * 控制发送速率
 * 作用：在数据包被确认后，执行拥塞控制逻辑，更新拥塞窗口；
 * 参数说明：
  * tcb: 当前连接的状态对象；
  * ackedPacket: 被确认的数据包；
  * alpha: 多路径调度中该路径的权重；
  * sum_rate: 所有路径的总速率；
 * 返回值：无；
 */
void
MpQuicCongestionOps::OnPacketAckedCC (Ptr<TcpSocketState> tcb,
                                    Ptr<QuicSocketTxItem> ackedPacket, double alpha, double sum_rate)
{
  NS_LOG_FUNCTION (this);
  // 将通用的 TcpSocketState 转换为具体的 QuicSocketState
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  // 如果转换失败则触发断言
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");

  NS_LOG_INFO ("Updating congestion window");
  if (InRecovery (tcb, ackedPacket->m_packetNumber)) // 判断是否处于恢复阶段
    {
      NS_LOG_LOGIC ("In recovery");
      // Do not increase congestion window in recovery period.
      return; // 在恢复阶段不增加拥塞窗口, 避免在丢包后重复反应
    }
  if (tcbd->m_cWnd < tcbd->m_ssThresh) // 慢启动阶段（Slow Start）
    {
      NS_LOG_LOGIC ("In slow start");
      // Slow start.
      // 在慢启动阶段，每收到一个 ACK，拥塞窗口线性增长（以数据包大小为单位）；
      tcbd->m_cWnd += ackedPacket->m_packet->GetSize ();
      // tcbd->m_cWnd += tcbd->m_segmentSize; // 固定大小增长
    }
  else // 拥塞避免阶段（Congestion Avoidance）
    {
      NS_LOG_LOGIC ("In congestion avoidance");
      // Congestion Avoidance.
      m_inCCAvoid = true;
      if (tcbd->m_cWnd > (uint32_t) 0) { // 确保拥塞窗口大于零
        // 计算拥塞窗口的增量
        double increase = (tcbd->m_cWnd/tcbd->m_segmentSize/pow(tcbd->m_lastRtt.Get().GetSeconds(),2))/pow(sum_rate,2)
                        + alpha/(tcbd->m_cWnd/tcbd->m_segmentSize);
        tcbd->m_cWnd += fabs(increase)*tcbd->m_segmentSize;
      } else {
          tcbd->m_cWnd = tcbd->m_kMinimumWindow;
      }
    }
}

/**
 * zhiy zeng: 处理丢包事件, 在检测到数据包丢失时被调用
 * 作用：当一组数据包被判断为丢失时，更新拥塞控制状态；
 * 参数说明：
  * tcb: 当前连接的状态对象；
  * lostPackets: 被判定为丢失的数据包列表；
 * 返回值：无；
 */
void
MpQuicCongestionOps::OnPacketsLost (
  Ptr<TcpSocketState> tcb, std::vector<Ptr<QuicSocketTxItem> > lostPackets)
{
  NS_LOG_LOGIC (this);
  // 将通用的 TcpSocketState 转换为具体的 QuicSocketState
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  // 如果转换失败则触发断言
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");

  // 获取最大编号的丢失包, 升序排列
  auto largestLostPacket = *(lostPackets.end () - 1);
  //for OLIA, 为 OLIA 等算法保存状态
  // 保存最近两次丢包前发送的数据量
  tcbd->m_bytesBeforeLost1 = tcbd->m_bytesBeforeLost2;
  tcbd->m_bytesBeforeLost2 = 0;

  NS_LOG_INFO ("Go in recovery mode");
  // Start a new recovery epoch if the lost packet is larger than the end of the previous recovery epoch.
  if (!InRecovery (tcbd, largestLostPacket->m_packetNumber))
    { // 判断是否进入新恢复阶段: 若当前最大丢失包不在恢复阶段内，则开启一个新的恢复阶段

      // 设置恢复结束标记: 表示直到这个数据包之后的所有确认都属于当前恢复阶段
      tcbd->m_endOfRecovery = tcbd->m_highTxMark; 
      // 减小拥塞窗口: 使用一个系数 kLossReductionFactor（通常小于 1，例如 0.5）减小窗口大小
      tcbd->m_cWnd *= tcbd->m_kLossReductionFactor;
      if (tcbd->m_cWnd < tcbd->m_kMinimumWindow) // 确保拥塞窗口不小于最小值
        {
          tcbd->m_cWnd = tcbd->m_kMinimumWindow;
        }
      // 更新慢启动阈值: 当前的 cWnd，表示下一次慢启动将从此值开始
      tcbd->m_ssThresh = tcbd->m_cWnd;
    }
}

/**
 * zhiy zeng: 处理验证后的重传超时（RTO）事件的回调函数, 在确认 
  * RTO 是“虚假”的情况下被调用，或者作为 RTO 机制的一部分来重置拥塞状态
 * 作用：当检测到一个 RTO 并且该 RTO 被认为是有效的（或需要进行清理）时，
  * 更新连接的拥塞状态；
 * 参数说明：
  * tcb: 当前连接的状态对象；
 * 返回值：无；
 */
void
MpQuicCongestionOps::OnRetransmissionTimeoutVerified (
  Ptr<TcpSocketState> tcb)
{
  NS_LOG_FUNCTION (this);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");
  NS_LOG_INFO ("Loss state");
  tcbd->m_cWnd = tcbd->m_kMinimumWindow; // 重置拥塞窗口到最小值
  tcbd->m_congState = TcpSocketState::CA_LOSS; // 设置当前状态为丢失状态
}

/**
 * 
 */
void
MpQuicCongestionOps::OnRetransmissionTimeout (Ptr<TcpSocketState> tcb)
{
  NS_LOG_FUNCTION (this);
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd != 0, "tcb is not a QuicSocketState");
  NS_LOG_INFO ("Time Out");
  tcbd->m_cWnd = tcbd->m_kMinimumWindow;
  tcbd->m_congState = TcpSocketState::CA_LOSS;
}

} // namespace ns3

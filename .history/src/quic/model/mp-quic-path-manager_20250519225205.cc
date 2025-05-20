/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2022 Pan Lab, Department of Computer Science, University of Victoria
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
 * Authors: Shengjie Shu <shengjies@uvic.ca>
 */

#include "ns3/object.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/boolean.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/nstime.h"
#include "quic-stream.h"
#include "ns3/node.h"
#include "ns3/string.h"


#include <algorithm>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <vector>


#include "mp-quic-path-manager.h"
#include "mp-quic-subflow.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("MpQuicPathManager");

NS_OBJECT_ENSURE_REGISTERED (MpQuicPathManager);

/**
 * zhiy zeng: 定义了 MpQuicPathManager 类的类型标识符（TypeId），
 * 以便 NS-3 的对象系统可以识别、实例化和管理该类
 */
TypeId
MpQuicPathManager::GetTypeId (void)
{
  // 定义了一个唯一的类型名称
  static TypeId tid = TypeId ("ns3::MpQuicPathManager")
    .SetParent<Object> () // 设置父类为 Object
    .SetGroupName ("Internet") // 设置组名为 Internet                 
  ;
  return tid;
}

/**
 * zhiy zeng: MpQuicPathManager 构造函数
 * 初始化了成员变量 m_socket、m_segSize 和 m_initialSsThresh
 */
MpQuicPathManager::MpQuicPathManager ()
  : m_socket(0),
  m_segSize(0),
  m_initialSsThresh(0)
{
  NS_LOG_FUNCTION_NOARGS ();
 
}

/**
 * zhiy zeng: MpQuicPathManager 析构函数
 * 释放了对象的资源
 */
MpQuicPathManager::~MpQuicPathManager ()
{
  NS_LOG_FUNCTION_NOARGS ();
  
}

/**
 * zhiy zeng: 初始化第一条子流（路径，Subflow 0）, 
  * 这条子流通常被称为“默认路径”或“初始路径”，
  * 它负责建立连接并作为后续新增路径的基础
 * 参数说明：
  * localAddress: 本地地址（通常是客户端的 IP 和端口）；
  * peerAddress: 对端地址（服务器的 IP 和端口）；
 * 返回值：指向新创建的子流对象（MpQuicSubFlow）；
 */
Ptr<MpQuicSubFlow>
MpQuicPathManager::InitialSubflow0 (Address localAddress, Address peerAddress)
{
  NS_LOG_FUNCTION(this);
  // 使用 NS-3 的对象系统创建一个新的子流对象
  Ptr<MpQuicSubFlow> sFlow = CreateObject<MpQuicSubFlow> ();
  sFlow->m_flowId    = 0; // 设置子流(路径) ID 为 0
  sFlow->m_peerAddr  = peerAddress; // 设置对端地址
  sFlow->m_localAddr = localAddress; // 设置本地地址
  sFlow->m_subflowState = MpQuicSubFlow::Active; // 设置子流状态为 Active
  sFlow->SetSegSize(m_segSize); // 将子流的最大报文段大小（Segment Size）设置
  // 为由 MpQuicPathManager 管理的 m_segSize
  sFlow->m_tcb->m_initialSsThresh = m_initialSsThresh; // 设置初始慢启动阈值
  m_socket->SubflowInsert(sFlow); // 将子流插入到 QUIC 套接字的子流列表中
  // 绑定回调函数, 这些回调使得socket可以统一处理多个子流的状态更新
  bool ok;
  // 拥塞窗口变化时触发的回调
  ok = sFlow->m_tcb->TraceConnectWithoutContext ("CongestionWindow", MakeCallback (&QuicSocketBase::UpdateCwnd, m_socket));
  NS_ASSERT_MSG (ok == true, "Failed connection to CWND0 trace");
  // 慢启动阈值变化时触发的回调
  ok = sFlow->m_tcb->TraceConnectWithoutContext ("SlowStartThreshold", MakeCallback (&QuicSocketBase::UpdateSsThresh, m_socket));
  NS_ASSERT_MSG (ok == true, "Failed connection to SSTHR0 trace");
  // RTT 测量更新时触发的回调
  ok = sFlow->m_tcb->TraceConnectWithoutContext ("RTT", MakeCallback (&QuicSocketBase::TraceRTT0, m_socket));
  NS_ASSERT_MSG (ok == true, "Failed connection to RTT0 trace");
  return sFlow;

}

/**
 * zhi zeng: 动态添加新的子流（路径）
  * 在建立初始连接后，用于向对端发起新的路径加入请求，实现多路径传输
 * 作用：创建并插入一个新的子流（subflow），用于支持 MP-QUIC 的多路径传输；
 * 参数说明：
  * localAddress: 新子流使用的本地地址；
  * peerAddress: 对端地址；
  * pathId: 子流的唯一标识符（路径 ID）；
 * 返回值：指向新创建的 MpQuicSubFlow 子流对象；
 */
Ptr<MpQuicSubFlow>
MpQuicPathManager::AddSubflow(Address localAddress, Address peerAddress, uint8_t pathId)
{
    
  NS_LOG_FUNCTION(this);
  // 创建一个新的子流对象
  Ptr<MpQuicSubFlow> sFlow = CreateObject<MpQuicSubFlow> ();
  sFlow->m_flowId    = pathId; // 设置子流 ID
  sFlow->m_localAddr = localAddress; // 设置本地地址
  sFlow->m_peerAddr = peerAddress; // 设置对端地址

  // 设置子流状态为 Validating，表示正在验证连接
  sFlow->m_subflowState = MpQuicSubFlow::Validating; 
  sFlow->SetSegSize(m_segSize); // 设置子流的最大报文段大小
  sFlow->m_tcb->m_initialSsThresh = m_initialSsThresh; // 设置初始慢启动阈值
  sFlow->m_tcb->m_cWnd = sFlow->m_tcb->m_initialCWnd; // 设置初始拥塞窗口
  sFlow->m_tcb->m_ssThresh = sFlow->m_tcb->m_initialSsThresh; // 设置初始慢启动阈值
  m_socket->SubflowInsert(sFlow); // 将新子流插入到 QUIC 套接字的子流列表中
  m_socket->AddPath(localAddress, peerAddress, pathId); // 将新子流的地址信息添加到 QUIC 套接字中
  m_socket->SendAddAddress(localAddress, pathId); // 发送ADD_ADDRESS 控制帧
  
  return sFlow;

}

/**
 * zhiy zeng: 添加带有指定对端地址的新子流（路径）
 * 与 AddSubflow(...) 类似，但此版本强调了明确的
 * 对端地址配置，并在创建后立即发送路径验证请求（PATH_CHALLENGE），
 * 以确认新路径的可达性
 * 作用：创建并初始化一个带指定对端地址的新子流；
 * 参数说明：
  * localAddress: 新子流使用的本地地址；
  * peerAddress: 对端地址；
  * pathId: 子流的唯一标识符（路径 ID）；
 * 返回值：指向新创建的 MpQuicSubFlow 子流对象；
 */
Ptr<MpQuicSubFlow>
MpQuicPathManager::AddSubflowWithPeerAddress(Address localAddress, Address peerAddress, uint8_t pathId)
{
  NS_LOG_FUNCTION(this);
  // 创建子流对象
  Ptr<MpQuicSubFlow> sFlow = CreateObject<MpQuicSubFlow> ();
  sFlow->m_flowId     = pathId; // 路径 ID，通常非零（0 为默认路径）
  sFlow->m_localAddr  = localAddress; // 本地地址
  sFlow->m_peerAddr   = peerAddress; // 对端地址
  // 设置子流状态为 Validating，表示正在验证连接
  sFlow->m_subflowState = MpQuicSubFlow::Validating;
  sFlow->SetSegSize(m_segSize); // 设置子流的最大报文段大小
  sFlow->m_tcb->m_initialSsThresh = m_initialSsThresh; // 设置初始慢启动阈值
  sFlow->m_tcb->m_cWnd = sFlow->m_tcb->m_initialCWnd; // 设置初始拥塞窗口
  sFlow->m_tcb->m_ssThresh = sFlow->m_tcb->m_initialSsThresh; // 设置初始慢启动阈值
  m_socket->SubflowInsert(sFlow); // 将新子流插入到 QUIC 套接字的子流列表中
  m_socket->SendPathChallenge(pathId); // 发送PATH_CHALLENGE 控制帧
  // 绑定回调函数（Trace Callbacks）
  bool ok;
  ok = sFlow->m_tcb->TraceConnectWithoutContext ("CongestionWindow", MakeCallback (&QuicSocketBase::UpdateCwnd1, m_socket));
  NS_ASSERT_MSG (ok == true, "Failed connection to CWND trace");
  ok = sFlow->m_tcb->TraceConnectWithoutContext ("SlowStartThreshold", MakeCallback (&QuicSocketBase::UpdateSsThresh1, m_socket));
  NS_ASSERT_MSG (ok == true, "Failed connection to SSTHR1 trace");
  ok = sFlow->m_tcb->TraceConnectWithoutContext ("RTT", MakeCallback (&QuicSocketBase::TraceRTT1, m_socket));
  NS_ASSERT_MSG (ok == true, "Failed connection to RTT1 trace");
  return sFlow;
}

/**
 * zhiy zeng: 设置 QUIC 套接字m_socket
 */
void
MpQuicPathManager::SetSocket(Ptr<QuicSocketBase> sock)
{
  NS_LOG_FUNCTION (this);
  m_socket = sock;
}

/**
 * zhiy zeng: 设置子流的最大报文段大小m_segSize
 */
void 
MpQuicPathManager::SetSegSize(uint32_t size)
{
  NS_LOG_FUNCTION(this);
  m_segSize = size;
}

/**
 * zhiy zeng: 获取子流的最大报文段大小m_segSize
 */
uint32_t 
MpQuicPathManager::GetSegSize() const
{
  NS_LOG_FUNCTION(this);
  return m_segSize;
}

/**
 * zhiy zeng: 设置初始慢启动阈值m_initialSsThresh
 */
void
MpQuicPathManager::SetInitialSSThresh (uint32_t threshold)
{
  m_initialSsThresh = threshold;
}

/**
 * zhiy zeng: 获取初始慢启动阈值m_initialSsThresh
 */
uint32_t
MpQuicPathManager::GetInitialSSThresh (void) const
{
  return m_initialSsThresh;
}


}
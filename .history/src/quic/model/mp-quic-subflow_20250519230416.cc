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


#include <stdint.h>
#include <iostream>
#include "ns3/buffer.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "mp-quic-subflow.h"
#include <stdlib.h>
#include <queue>
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include <ns3/object-base.h>
#include "ns3/simulator.h"
#include "time.h"
#include "ns3/string.h"

#include "quic-socket-tx-scheduler.h"
#include "quic-socket-base.h"

#include <algorithm>
#include <math.h>
#include <cmath>

NS_LOG_COMPONENT_DEFINE ("MpQuicSubFlow");
namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (MpQuicSubFlow);

/**
 * zhiy zeng: 定义了 MpQuicSubFlow 类的类型标识符（TypeId）
 * 
 */
TypeId
MpQuicSubFlow::GetTypeId (void)
{
    static TypeId tid = TypeId ("ns3::MpQuicSubFlow")
        .SetParent (Object::GetTypeId ()) // 设置父类为 Object
        // 添加 Trace 源：拥塞窗口（CWindow）
        .AddTraceSource ("CWindow", // 追踪源的名字
                     "The QUIC connection's congestion window",
                     // 将追踪源绑定到成员变量 m_cWndTrace
                     MakeTraceSourceAccessor (&MpQuicSubFlow::m_cWndTrace),
                     "ns3::TracedValueCallback::Uint32")
        ;
      return tid;
}

/**
 * zhiy zeng: MpQuicSubFlow 构造函数, 用于初始化 MP-QUIC 子流对象（即每条独立路径）
 * 初始化了成员变量 m_flowId、m_lastMaxData、
 * m_maxDataInterval 和 m_rounds
 */
MpQuicSubFlow::MpQuicSubFlow()
    : m_flowId (0), // 路径 ID，默认为 0
      m_lastMaxData(0), // 上一次发送的 MAX_DATA 值, 默认为 0
      m_maxDataInterval(10), // 发送 MAX_DATA 的间隔，默认为 10
      m_rounds(1) // 轮数，默认为 1
{
    // 自上次发送 ACK 以来收到的数据包数量
    m_numPacketsReceivedSinceLastAckSent = 0;
    m_queue_ack = false;  // 是否需要排队发送 ACK
    // 缓存已收到的数据包编号，用于检测丢包和乱序
    m_receivedPacketNumbers = std::vector<SequenceNumber32> ();

    //For congestion control
    // m_tcb 是传输控制块（Transmission Control Block），
    // 用于管理拥塞控制、RTT、窗口等状态
    m_tcb = CreateObject<QuicSocketState> ();
    m_tcb->m_cWnd = m_tcb->m_initialCWnd; // 初始化拥塞窗口
    m_tcb->m_ssThresh = m_tcb->m_initialSsThresh; // 初始化慢启动阈值
    m_tcb->m_pacingRate = m_tcb->m_maxPacingRate; // 初始化节流速率

    // connect callbacks
    bool ok;
    // 绑定 Trace 回调到 CongestionWindow
    // 当拥塞窗口发生变化时，会触发回调函数 UpdateCwnd(...)
    ok = m_tcb->TraceConnectWithoutContext ("CongestionWindow",
                                            MakeCallback (&MpQuicSubFlow::UpdateCwnd, this));
    NS_ASSERT_MSG (ok == true, "Failed connection to CWND trace");

}

MpQuicSubFlow::~MpQuicSubFlow()
{
    m_flowId     = 0;
}


/**
 * zhiy zeng: 设置子流的最大报文段大小
 * 设置子流的初始拥塞窗口和最小窗口大小
 */
void
MpQuicSubFlow::SetSegSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);

  m_tcb->m_segmentSize = size;
  m_tcb->m_initialCWnd = 2 * size;
  m_tcb->m_kMinimumWindow = 2 * size;
}

uint32_t
MpQuicSubFlow::GetSegSize (void) const
{
  return m_tcb->m_segmentSize;
}

double
MpQuicSubFlow::GetRate()
{
    if (m_tcb->m_lastRtt.Get().GetSeconds() == 0){
        return 0;
    }
    return m_tcb->m_cWnd/m_tcb->m_segmentSize/m_tcb->m_lastRtt.Get().GetSeconds();
} 

void
MpQuicSubFlow::UpdateCwnd (uint32_t oldValue, uint32_t newValue)
{
  m_cWndTrace (oldValue, newValue);
}


} // namespace ns3

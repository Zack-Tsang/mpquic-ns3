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
#include <bitset>
#include <numeric>

#include "mp-quic-scheduler.h"
#include "ns3/random-variable-stream.h"


using Eigen::MatrixXd;
using Eigen::VectorXd;

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("MpQuicScheduler");

NS_OBJECT_ENSURE_REGISTERED (MpQuicScheduler);

/**
 * zhiy zeng: 用于注册调度器类类型信息, 定义了 MpQuicScheduler 
  * 的属性（Attributes）和元数据，使得该类可以在 NS-3 模拟环境中
  * 被配置、实例化并使用
 * 作用：为 MpQuicScheduler 类型提供唯一的标识符，并注册其可配置的属性；
 * 返回值：一个 TypeId 实例，用于在 NS-3 内部识别这个类；
 */
TypeId
MpQuicScheduler::GetTypeId (void)
{
  // 静态变量 tid 用于存储 MpQuicScheduler 的类型信息
  static TypeId tid = TypeId ("ns3::MpQuicScheduler")
    .SetParent<Object> () // 设置 MpQuicScheduler 的父类为 Object
    .SetGroupName ("Internet") // 设置 MpQuicScheduler 的分组名称为 Internet
    // 属性注册
    .AddAttribute ("SchedulerType", // 属性名
                   "define the type of the scheduler", // 属性描述
                   IntegerValue (MIN_RTT), // 默认值
                   // 关联到成员变量 m_schedulerType
                   MakeIntegerAccessor (&MpQuicScheduler::m_schedulerType),
                   // 数据类型限制
                   MakeIntegerChecker<int16_t> ())
    .AddAttribute ("MabRate", // 用于 Multi-Armed Bandit（MAB）调度策略中的探索/利用比率
                   "define the rate of the MAB scheduler",
                   UintegerValue (100),
                   MakeUintegerAccessor (&MpQuicScheduler::m_rate),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("BlestLambda", 
                   "define the lambda of the BLEST",
                   UintegerValue (1000),
                   MakeUintegerAccessor (&MpQuicScheduler::m_lambda),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("BlestVar",
                   "define the lambda of the BLEST",
                   UintegerValue (100),
                   MakeUintegerAccessor (&MpQuicScheduler::m_bVar),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("Select",
                   "string of select",
                   UintegerValue (0),
                   MakeUintegerAccessor (&MpQuicScheduler::m_select),
                   MakeUintegerChecker<uint16_t> ())            
     
  ;
  return tid;
}

/**
 * zhiy zeng: MpQuicScheduler构造函数, 初始化成员变量
 */
MpQuicScheduler::MpQuicScheduler ()
  : Object (), // 调用父类构造函数
  m_socket(0), // 指向关联的 Quic socket, 默认为空
  m_lastUsedPathId(0), // 上次使用的路径 ID, 默认为 0
  m_select(0) // ?
{
  NS_LOG_FUNCTION_NOARGS ();
  m_lastUpdateRounds = 1; // 上次更新的轮数, 默认为 1
  m_e = 0; // ?
}

/**
 * zhiy zeng: MpQuicScheduler析构函数, 释放资源
 */
MpQuicScheduler::~MpQuicScheduler ()
{
  NS_LOG_FUNCTION_NOARGS ();
}


/**
 * zhiy zeng: 根据当前设置的调度策略（如 Round Robin、
  * Min RTT、BLEST、ECF及Peekaboo）选择下一条用于发送
  * 数据包的子流（路径）,并返回一个表示各路径使用概率的向量
 * 返回值类型：std::vector<double>，每个元素代表对应子流被选中的“概率”；
 * 用途：为 MP-QUIC 提供多路径选择依据；
 */
std::vector<double> 
MpQuicScheduler::GetNextPathIdToUse()
{
  m_subflows = m_socket->GetActiveSubflows(); // 获取当前活动的子流
  // 创建一个与子流数量一致的向量，初始值为 0.0, 每个位置代表该子流被使用的概率
  std::vector<double> tosend(m_subflows.size(), 0.0); 
  if (m_subflows.empty()) // 如果没有活动的子流
  {
    tosend.push_back(1.0); // tosend: 0: 1.0
    return tosend;
  }
  switch (m_schedulerType) // 根据调度策略选择路径
  {
    case ROUND_ROBIN:
      tosend = RoundRobin();
      break;

    case MIN_RTT:
      tosend = MinRtt();
      break;
    
    case BLEST:
      tosend = Blest();
      break;

    case ECF:
      tosend = Ecf();
      break;

    case PEEKABOO:
      tosend = Peekaboo();
      break;

    default: // 默认使用 Round Robin 策略
      tosend = RoundRobin();
      break;
      
  }

  return tosend;
}

/**
 * zhiy zeng: Round Robin 调度策略
  * 轮询调度算法, 依次选择每个子流进行数据传输
 * 返回值类型：std::vector<double>，每个元素表示对应子流被选中的权重；
 */
std::vector<double>
MpQuicScheduler::RoundRobin()
{
  std::vector<double> tosend(m_subflows.size(), 0.0);
  if (m_subflows.size() <= 1){
    m_lastUsedPathId = 0;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }

  m_lastUsedPathId = (m_lastUsedPathId + 1) % m_subflows.size();

  tosend[m_lastUsedPathId] = 1.0;
  return tosend;
}

/**
 * zhiy zeng: Min RTT 调度策略
  * 选择 RTT 最小的子流进行数据传输
 */
std::vector<double>
MpQuicScheduler::MinRtt()
{
  NS_LOG_FUNCTION (this);
  // 创建一个全为 0.0 的概率向量
  std::vector<double> tosend(m_subflows.size(), 0.0);

  // 仅有一条路径
  if (m_subflows.size() <= 1){
    m_lastUsedPathId = 0;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }

  // 如果第二条路径的 RTT 为 0，直接使用第二条路径
  if (m_subflows[1]->m_tcb->m_lastRtt.Get().GetSeconds() == 0) {
    m_lastUsedPathId = 1;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }

  Time rttS;
  Time rttF;
  uint8_t fastPathId = 1;
  uint8_t slowPathId = 0;

  if (m_subflows[0]->m_tcb->m_lastRtt >= m_subflows[1]->m_tcb->m_lastRtt){
    rttS = m_subflows[0]->m_tcb->m_lastRtt;
    rttF = m_subflows[1]->m_tcb->m_lastRtt;
    slowPathId = 0;
    fastPathId = 1;
  } else {
    rttS = m_subflows[1]->m_tcb->m_lastRtt;
    rttF = m_subflows[0]->m_tcb->m_lastRtt;
    slowPathId = 1;
    fastPathId = 0;
  }

  if (m_socket->AvailableWindow (fastPathId) > 0){
    m_lastUsedPathId = fastPathId;
  }else {
    m_lastUsedPathId = slowPathId;
  }

  tosend[m_lastUsedPathId] = 1.0;
  return tosend;
}

void
MpQuicScheduler::SetSocket(Ptr<QuicSocketBase> sock)
{
  NS_LOG_FUNCTION (this);
  m_socket = sock;
}


std::vector<double>
MpQuicScheduler::Blest() //only allow two subflows
{
  NS_LOG_FUNCTION (this);
  std::vector<double> tosend(m_subflows.size(), 0.0);

  if (m_subflows.size() <= 1){
    m_lastUsedPathId = 0;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }

  if (m_subflows[1]->m_tcb->m_lastRtt.Get().GetSeconds() == 0) {
    m_lastUsedPathId = 1;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }
  
  Time rttS;
  Time rttF;
  uint8_t fastPathId = 1;
  uint8_t slowPathId = 0;
  uint32_t mss = m_socket->GetSegSize();

  if (m_subflows[0]->m_tcb->m_lastRtt > m_subflows[1]->m_tcb->m_lastRtt){
    rttS = m_subflows[0]->m_tcb->m_lastRtt;
    rttF = m_subflows[1]->m_tcb->m_lastRtt;
    slowPathId = 0;
    fastPathId = 1;
  } else {
    rttS = m_subflows[1]->m_tcb->m_lastRtt;
    rttF = m_subflows[0]->m_tcb->m_lastRtt;
    slowPathId = 1;
    fastPathId = 0;
  }

  if (m_socket->AvailableWindow (fastPathId) > 0){
    m_lastUsedPathId = fastPathId;
  } else {
    double_t rtts = rttS.GetSeconds()/rttF.GetSeconds();
    double_t cwndF = m_subflows[fastPathId]->m_tcb->m_cWnd/mss;
    double_t X = mss * (cwndF + (rtts-1)/2) * rtts;
    double_t comp = m_socket->GetTxAvailable() - (m_socket->BytesInFlight(slowPathId)+mss);
    m_lambda = m_lambda + m_bVar;
    if(X * m_lambda > comp) { //not send on slow path
      m_lastUsedPathId = fastPathId;
    } else {
      m_lastUsedPathId = slowPathId;
    }
  }
  
  tosend[m_lastUsedPathId] = 1.0;
  return tosend;
}


std::vector<double>
MpQuicScheduler::Ecf() //only allow two subflows
{
  NS_LOG_FUNCTION (this);
  std::vector<double> tosend(m_subflows.size(), 0.0);
  if (m_subflows.size() <= 1){
    m_lastUsedPathId = 0;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }

  if (m_subflows[1]->m_tcb->m_lastRtt.Get().GetSeconds() == 0) {
    m_lastUsedPathId = (m_lastUsedPathId + 1) % m_subflows.size();
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  } 
  
  
  Time rttS;
  Time rttF;
  uint8_t fastPathId = 1;
  uint8_t slowPathId = 0;

  if (m_subflows[0]->m_tcb->m_lastRtt > m_subflows[1]->m_tcb->m_lastRtt){
    rttS = m_subflows[0]->m_tcb->m_lastRtt;
    rttF = m_subflows[1]->m_tcb->m_lastRtt;
    slowPathId = 0;
    fastPathId = 1;
  } else {
    rttS = m_subflows[1]->m_tcb->m_lastRtt;
    rttF = m_subflows[0]->m_tcb->m_lastRtt;
    slowPathId = 1;
    fastPathId = 0;
  }

  if (m_socket->AvailableWindow (fastPathId) > 0){
    m_lastUsedPathId = fastPathId;
  }else {
    uint32_t k = m_socket->GetBytesInBuffer();
    double n = 1 + k/m_subflows[fastPathId]->m_tcb->m_cWnd.Get();
    double delta = max(m_subflows[fastPathId]->m_tcb->m_rttVar.GetSeconds(),m_subflows[slowPathId]->m_tcb->m_rttVar.GetSeconds());
    if (n*rttF.GetSeconds() < (1+m_waiting*1)*(rttS.GetSeconds()+delta)){
      if (k/m_subflows[slowPathId]->m_tcb->m_cWnd.Get() * rttS.GetSeconds() >= 2*rttF.GetSeconds()+delta){
        m_waiting = 1;
        m_lastUsedPathId = fastPathId;
        tosend[m_lastUsedPathId] = 1.0;
        return tosend;
      } else {
        m_lastUsedPathId = slowPathId;
      }
    } else {
      m_waiting = 0;
      m_lastUsedPathId = slowPathId;
    }
  }  

  tosend[m_lastUsedPathId] = 1.0;
  return tosend;
}

std::vector<double>
MpQuicScheduler::Peekaboo()
{
  NS_LOG_FUNCTION (this);
  uint8_t K = m_subflows.size();
  if(EPR.size() < K)
  {
    EPR.push_back(0.0);
    A.push_back(MatrixXd::Identity(6,6));
    b.push_back(VectorXd::Constant(6,0));
  }
  std::vector<double> tosend(m_subflows.size(), 0.0);

  if (m_subflows.size() <= 1){
    m_lastUsedPathId = 0;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }
  if (m_subflows[1]->m_tcb->m_lastRtt.Get().GetSeconds() == 0) {
    m_lastUsedPathId = 1;
    tosend[m_lastUsedPathId] = 1.0;
    return tosend;
  }

  Time rttS;
  Time rttF;
  uint8_t fastPathId = 1;
  uint8_t slowPathId = 0;

  if (m_subflows[0]->m_tcb->m_lastRtt >= m_subflows[1]->m_tcb->m_lastRtt){
    rttS = m_subflows[0]->m_tcb->m_lastRtt;
    rttF = m_subflows[1]->m_tcb->m_lastRtt;
    slowPathId = 0;
    fastPathId = 1;
  } else {
    rttS = m_subflows[1]->m_tcb->m_lastRtt;
    rttF = m_subflows[0]->m_tcb->m_lastRtt;
    slowPathId = 1;
    fastPathId = 0;
  }

  if (m_socket->AvailableWindow (fastPathId) > 0){
    m_lastUsedPathId = fastPathId;
  }else {
    for (int i = 0; i < 2; i++){
      MatrixXd zeta = A[i]*b[i];
      EPR[i] = (peek_x.transpose() * zeta).value() + 0.8 * std::sqrt(peek_x.transpose() * A[i].inverse() * peek_x);
    }

    if(EPR[fastPathId] > EPR[slowPathId]){
      m_lastUsedPathId = fastPathId; //wait
    } else {
      m_lastUsedPathId = slowPathId; //transmit on slow path
    }

    A[m_lastUsedPathId] = A[m_lastUsedPathId] + peek_x * peek_x.transpose();
    b[m_lastUsedPathId] = b[m_lastUsedPathId] + R * peek_x;

  }

  tosend[m_lastUsedPathId] = 1.0;
  return tosend;

}


void
MpQuicScheduler::PeekabooReward(uint8_t pathId, Time lastActTime)
{
  NS_LOG_FUNCTION (this);
  
  rtt[pathId] = m_subflows[pathId]->m_tcb->m_lastRtt.Get().GetDouble();
  if (rtt[0]==0) rtt[0] = 10;     // initialize rtt0 with 20ms
  if (rtt[1]==0) rtt[1] = 10;     // initialize rtt0 with 20ms
  if(pathId == 0){
    peek_x[0] = m_subflows[pathId]->m_tcb->m_cWnd.Get()/rtt[pathId];
    peek_x[1] = m_subflows[pathId]->m_tcb->m_bytesInFlight.Get()/rtt[pathId];
    peek_x[2] = m_subflows[pathId]->m_tcb->m_cWnd.Get()/rtt[pathId];
  } else{
    peek_x[3] = m_subflows[pathId]->m_tcb->m_cWnd.Get()/rtt[pathId];
    peek_x[4] = m_subflows[pathId]->m_tcb->m_bytesInFlight.Get()/rtt[pathId];
    peek_x[5] = m_subflows[pathId]->m_tcb->m_cWnd.Get()/rtt[pathId];
  }


  double rtt_f = std::min(rtt[0], rtt[1]);
  double rtt_s = std::max(rtt[0], rtt[1]);

  T_r = std::max(2*rtt_f, rtt_s);
  T_e = (Now () - lastActTime).GetMilliSeconds();
  if (T_e < 3 * T_r)
    {
      double r = 1460 * 1000 * 1e9/ (Now() - lastActTime).GetDouble();
      R = R + r * g;
      if (T_e <= T_r)
        {
          g = 0.9 * g;
        }
      else if (T_e <= 2 * T_r)
        {
          g = 0.7 * g;
        }
      else
        {
          g = 0.5 * g;
        }
    }
  
  
}


void
MpQuicScheduler::SetNumOfLostPackets(uint16_t lost){
  m_lostPackets = lost;
}


} // namespace ns3

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007,2008,2009 INRIA, UDCAST
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
 * Author: Amine Ismail <amine.ismail@sophia.inria.fr>
 *                      <amine.ismail@udcast.com>
 */
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "quic-client.h"
#include "seq-ts-header.h"
#include <cstdlib>
#include <cstdio>

/**
 * zhiy zeng: QuicClient 类的完整实现，它继承自 NS-3 的 Application 基类，
  * 封装了 QUIC 客户端的基本行为：连接、发送数据包、管理流（streams）、以及与
  * socket 交互等。
 */

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicClient");

NS_OBJECT_ENSURE_REGISTERED (QuicClient);

/**
 * zhiy zeng: 注册 QuicClient 类型并定义其可配置属性
 */
TypeId
QuicClient::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicClient")
    .SetParent<Application> () // 继承自 Application 基类
    .SetGroupName ("Applications") // 设置分组名称
    .AddConstructor<QuicClient> () // 添加构造函数
    .AddAttribute ("MaxPackets", // 最大发包数
                   "The maximum number of packets the application will send",
                   UintegerValue (100),
                   MakeUintegerAccessor (&QuicClient::m_count),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Interval", // 发包间隔时间
                   "The time to wait between packets", TimeValue (Seconds (1.0)),
                   MakeTimeAccessor (&QuicClient::m_interval),
                   MakeTimeChecker ())
    .AddAttribute ("RemoteAddress", // 远程地址
                   "The destination Address of the outbound packets",
                   AddressValue (),
                   MakeAddressAccessor (&QuicClient::m_peerAddress),
                   MakeAddressChecker ())
    // 目标端口
    .AddAttribute ("RemotePort", "The destination port of the outbound packets",
                   UintegerValue (100),
                   MakeUintegerAccessor (&QuicClient::m_peerPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("PacketSize", // 数据包大小
                   "Size of packets generated. The minimum packet size is 12 bytes which is the size of the header carrying the sequence number and the time stamp.",
                   UintegerValue (1024),
                   MakeUintegerAccessor (&QuicClient::m_size),
                   MakeUintegerChecker<uint32_t> (12,1500))
    .AddAttribute ("NumStreams", // 使用的流数量
                   "Number of streams to be used in the underlying QUIC socket",
                   UintegerValue (1),
                   MakeUintegerAccessor (&QuicClient::m_numStreams),
                   MakeUintegerChecker<uint32_t> (1,20)) // TODO check the max value
  ;
  return tid;
}

QuicClient::QuicClient ()
{
  NS_LOG_FUNCTION (this);
  m_sent = 0;
  m_socket = 0;
  m_lastUsedStream = 1;
  m_sendEvent = EventId ();
}

QuicClient::~QuicClient ()
{
  NS_LOG_FUNCTION (this);
}

void
QuicClient::SetRemote (Address ip, uint16_t port)
{
  NS_LOG_FUNCTION (this << ip << port);
  m_peerAddress = ip;
  m_peerPort = port;
}

void
QuicClient::SetRemote (Address addr)
{
  NS_LOG_FUNCTION (this << addr);
  m_peerAddress = addr;
}

void
QuicClient::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  Application::DoDispose ();
}

void
QuicClient::StartApplication (void)
{
  NS_LOG_FUNCTION (this);

  if (m_socket == 0)
    {
      TypeId tid = TypeId::LookupByName ("ns3::QuicSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      if (Ipv4Address::IsMatchingType (m_peerAddress) == true)
        {
          if (m_socket->Bind () == -1)
            {
              NS_FATAL_ERROR ("Failed to bind socket");
            }
          m_socket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom (m_peerAddress), m_peerPort));
        }
      else if (Ipv6Address::IsMatchingType (m_peerAddress) == true)
        {
          if (m_socket->Bind6 () == -1)
            {
              NS_FATAL_ERROR ("Failed to bind socket");
            }
          m_socket->Connect (Inet6SocketAddress (Ipv6Address::ConvertFrom (m_peerAddress), m_peerPort));
        }
      else if (InetSocketAddress::IsMatchingType (m_peerAddress) == true)
        {
          if (m_socket->Bind () == -1)
            {
              NS_FATAL_ERROR ("Failed to bind socket");
            }
          m_socket->Connect (m_peerAddress);
        }
      else if (Inet6SocketAddress::IsMatchingType (m_peerAddress) == true)
        {
          if (m_socket->Bind6 () == -1) \
            {
              NS_FATAL_ERROR ("Failed to bind socket");
            }
          m_socket->Connect (m_peerAddress);
        }
      else
        {
          NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
        }
    }

  m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
  m_socket->SetAllowBroadcast (true);
  m_sendEvent = Simulator::Schedule (Seconds (0), &QuicClient::Send, this);
}

void
QuicClient::StopApplication (void)
{
  NS_LOG_FUNCTION (this);
  Simulator::Cancel (m_sendEvent);
  if (m_socket != 0)
    {
      m_socket->Close ();
      m_socket = 0;
    }
}

void
QuicClient::Send (void)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_sendEvent.IsExpired ());
  SeqTsHeader seqTs;
  seqTs.SetSeq (m_sent);
  Ptr<Packet> p = Create<Packet> (m_size); // 8+4 : the size of the seqTs header
  // p->AddHeader (seqTs);

  std::stringstream peerAddressStringStream;
  if (Ipv4Address::IsMatchingType (m_peerAddress))
    {
      peerAddressStringStream << Ipv4Address::ConvertFrom (m_peerAddress);
    }
  else if (Ipv6Address::IsMatchingType (m_peerAddress))
    {
      peerAddressStringStream << Ipv6Address::ConvertFrom (m_peerAddress);
    }

  if ((m_socket->Send (p, m_lastUsedStream)) >= 0)
    {
      ++m_sent;
      NS_LOG_INFO ("TraceDelay TX " << m_size << " bytes to "
                                    << peerAddressStringStream.str () << " Uid: "
                                    << p->GetUid () << " Time: "
                                    << (Simulator::Now ()).GetSeconds ());

    }
  else
    {
      NS_LOG_INFO ("Error while sending " << m_size << " bytes to "
                                          << peerAddressStringStream.str ());
    }

  // apply a round robin policy for the streams (i.e., one packet per stream)
  m_lastUsedStream++;
  if (m_lastUsedStream > m_numStreams)
    {
      m_lastUsedStream = 1;
    }

  if (m_sent < m_count)
    {
      m_sendEvent = Simulator::Schedule (m_interval, &QuicClient::Send, this);
    }
}

} // Namespace ns3

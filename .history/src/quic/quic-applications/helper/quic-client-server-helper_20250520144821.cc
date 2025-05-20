/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
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
 * Author: Mohamed Amine Ismail <amine.ismail@sophia.inria.fr>
 */
#include "quic-client-server-helper.h"
#include "ns3/quic-server.h"
#include "ns3/quic-client.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"

/**
 * NS-3 中 QUIC 协议的客户端和服务器辅助类，用于简化在仿真中
 * 创建 QUIC 客户端和服务端应用程序的过程。它们属于 ns3 命名
 * 空间，使用了 NS-3 的对象工厂机制（ObjectFactory）来实例化
 *  QUIC 应用程序。
 */

namespace ns3 {

/**
 * zhiy zeng: QuicServerHelper类的默认构造函数
 */
QuicServerHelper::QuicServerHelper ()
{
  // 设置默认的 TypeId 为 QuicServer
  // 使用 ObjectFactory 创建对象
  m_factory.SetTypeId (QuicServer::GetTypeId ());
}

/**
 * zhiy zeng: QuicServerHelper类指定端口的构造函数
 */
QuicServerHelper::QuicServerHelper (uint16_t port)
{
  m_factory.SetTypeId (QuicServer::GetTypeId ());
  SetAttribute ("Port", UintegerValue (port));
}

/**
 * zhiy zeng: 用于设置 QUIC 服务端的任意属性
 */
void
QuicServerHelper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

/**
 * zhiy zeng: 在给定节点上安装 QUIC 服务端应用
  * 返回 ApplicationContainer，可用于后续控制或查询状态
 */
ApplicationContainer
QuicServerHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      Ptr<Node> node = *i;

      m_server = m_factory.Create<QuicServer> ();
      node->AddApplication (m_server);
      apps.Add (m_server);

    }
  return apps;
}

/**
 * zhiy zeng: 返回最后一次创建的 QuicServer 实例
  * 可用于直接调用服务端的方法或获取其状态
 */
Ptr<QuicServer>
QuicServerHelper::GetServer (void)
{
  return m_server;
}

/**
 * zhiy zeng: QuicClientHelper类的默认构造函数
 */
QuicClientHelper::QuicClientHelper ()
{
  m_factory.SetTypeId (QuicClient::GetTypeId ());
}

/**
 * zhiy zeng: QuicClientHelper类指定地址和端口的构造函数
 */
QuicClientHelper::QuicClientHelper (Address address, uint16_t port)
{
  m_factory.SetTypeId (QuicClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (address));
  SetAttribute ("RemotePort", UintegerValue (port));
}

/**
 * zhiy zeng: QuicClientHelper类指定地址的构造函数
 */
QuicClientHelper::QuicClientHelper (Address address)
{
  m_factory.SetTypeId (QuicClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (address));
}

/**
 * zhiy zeng: 用于设置 QUIC 客户端的任意属性
 */
void
QuicClientHelper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

/**
 * zhiy zeng: 在给定节点上安装 QUIC 客户端应用
  * 返回 所有客户端组成的容器，可用于后续控制或查询状态
 */
ApplicationContainer
QuicClientHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      Ptr<Node> node = *i;
      Ptr<QuicClient> client = m_factory.Create<QuicClient> ();
      node->AddApplication (client);
      apps.Add (client);
    }
  return apps;
}

} // namespace ns3

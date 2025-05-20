/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 * Authors: Davide Marcato <davide.marcato.4@studenti.unipd.it>
 *          Stefano Ravazzolo <stefano.ravazzolo@studenti.unipd.it>
 *          Alvise De Biasio <alvise.debiasio@studenti.unipd.it>
 */

 /**
  * zhiy zeng: NS-3 中 QUIC Echo 协议的客户端和服务器辅助类实现，用于在仿真
  * 中快速部署 QuicEchoServer 和 QuicEchoClient 应用程序。它基于 NS-3 的标
  * 准应用安装模式，使用了 ObjectFactory、ApplicationContainer、节点绑定等机制。
  * 
  */
#include "quic-echo-helper.h"
#include "ns3/quic-echo-server.h"
#include "ns3/quic-echo-client.h"
#include "ns3/uinteger.h"
#include "ns3/names.h"
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE ("QuicEchoHelper");

namespace ns3 {

/**
 * zhiy zeng: QuicEchoServerHelper类的构造函数
  * 设置默认 TypeId 为 QuicEchoServer
  * 配置监听端口
 */
QuicEchoServerHelper::QuicEchoServerHelper (uint16_t port)
{
  m_factory.SetTypeId (QuicEchoServer::GetTypeId ());
  SetAttribute ("Port", UintegerValue (port));
}

/**
 * zhiy zeng: 设置服务端任意可配置属性
 */
void
QuicEchoServerHelper::SetAttribute (
  std::string name,
  const AttributeValue &value)
{
  m_factory.Set (name, value);
}

/**
 * zhiy zeng: 将QuicEchoServerHelper安装到单个节点
 */
ApplicationContainer
QuicEchoServerHelper::Install (Ptr<Node> node) const
{
  return ApplicationContainer (InstallPriv (node));
}

/**
 * zhiy zeng: 将QuicEchoServerHelper安装到命名节点
 */
ApplicationContainer
QuicEchoServerHelper::Install (std::string nodeName) const
{
  Ptr<Node> node = Names::Find<Node> (nodeName);
  return ApplicationContainer (InstallPriv (node));
}

/**
 * zhiy zeng: 将QuicEchoServerHelper安装到多个节点
 */
ApplicationContainer
QuicEchoServerHelper::Install (NodeContainer c) const
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      apps.Add (InstallPriv (*i));
    }

  return apps;
}

/** 
 * zhiy zeng: 私有安装函数
  * 创建并安装一个 QuicEchoServer 到指定节点
  * 添加日志信息以便调试
 */
Ptr<Application>
QuicEchoServerHelper::InstallPriv (Ptr<Node> node) const
{

  Ptr<Application> app = m_factory.Create<QuicEchoServer> ();
  node->AddApplication (app);
  NS_LOG_INFO ("Installing app " << app << " in node " << node);
  return app;
}

/**
 * zhiy zeng: QuicEchoClientHelper类指定地址和端口的构造函数
  * 设置默认 TypeId 为 QuicEchoClient
  * 配置远程地址和端口
 */
QuicEchoClientHelper::QuicEchoClientHelper (Address address, uint16_t port)
{
  m_factory.SetTypeId (QuicEchoClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (address));
  SetAttribute ("RemotePort", UintegerValue (port));
}

/**
 * zhiy zeng: QuicEchoClientHelper类指定地址的构造函数
  * 设置默认 TypeId 为 QuicEchoClient
  * 配置远程地址
 */
QuicEchoClientHelper::QuicEchoClientHelper (Address address)
{
  m_factory.SetTypeId (QuicEchoClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (address));
}

/**
 * zhiy zeng: 设置客户端任意可配置属性
 */
void
QuicEchoClientHelper::SetAttribute (
  std::string name,
  const AttributeValue &value)
{
  m_factory.Set (name, value);
}

/**
 * zhiy zeng: 数据填充设置方法, 允许用户配置客户端发送的数据内容
  * 固定字符串
 */
void
QuicEchoClientHelper::SetFill (Ptr<Application> app, std::string fill)
{
  app->GetObject<QuicEchoClient>()->SetFill (fill);
}

/**
 * zhiy zeng: 数据填充设置方法, 允许用户配置客户端发送的数据内容
  * 固定字节
 */
void
QuicEchoClientHelper::SetFill (Ptr<Application> app, uint8_t fill, uint32_t dataLength)
{
  app->GetObject<QuicEchoClient>()->SetFill (fill, dataLength);
}

/**
 * zhiy zeng: 数据填充设置方法, 允许用户配置客户端发送的数据内容
  * 固定字节数组
 */
void
QuicEchoClientHelper::SetFill (Ptr<Application> app, uint8_t *fill, uint32_t fillLength, uint32_t dataLength)
{
  app->GetObject<QuicEchoClient>()->SetFill (fill, fillLength, dataLength);
}

ApplicationContainer
QuicEchoClientHelper::Install (Ptr<Node> node) const
{
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
QuicEchoClientHelper::Install (std::string nodeName) const
{
  Ptr<Node> node = Names::Find<Node> (nodeName);
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
QuicEchoClientHelper::Install (NodeContainer c) const
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      apps.Add (InstallPriv (*i));
    }

  return apps;
}

Ptr<Application>
QuicEchoClientHelper::InstallPriv (Ptr<Node> node) const
{
  Ptr<Application> app = m_factory.Create<QuicEchoClient> ();
  node->AddApplication (app);

  return app;
}

} // namespace ns3

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
 */

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/nstime.h"
#include "ns3/boolean.h"
#include "ns3/object-vector.h"
#include "ns3/pointer.h"

#include "ns3/packet.h"
#include "ns3/node.h"
#include "ns3/simulator.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv6-route.h"

#include "quic-l4-protocol.h"
#include "quic-header.h"
#include "ns3/ipv4-end-point-demux.h"
#include "ns3/ipv6-end-point-demux.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ipv6-end-point.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "quic-socket-factory.h"
#include "ns3/tcp-congestion-ops.h"
#include "quic-congestion-ops.h"
#include "ns3/rtt-estimator.h"
#include "ns3/random-variable-stream.h"

#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <math.h>
#include <iostream>

namespace ns3 {

// 确保 QuicL4Protocol 类在 NS-3 中被正确注册, zhiy zeng 
NS_OBJECT_ENSURE_REGISTERED (QuicL4Protocol);
NS_OBJECT_ENSURE_REGISTERED (QuicUdpBinding);
// 定义了一个日志组件，名为 "QuicL4Protocol"
// 允许开发者针对 "QuicL4Protocol" 组件调整日志级别、
// 查看特定于该组件的日志输出等, zhiy zeng
NS_LOG_COMPONENT_DEFINE ("QuicL4Protocol");

/*
作用：QuicUdpBinding 类的构造函数，初始化该类的成员变量，
为后续 QUIC 协议与 UDP 套接字之间的绑定操作做准备。用于在 
NS-3 中实现 QUIC over UDP 的网络通信;

zhiy zeng
*/
QuicUdpBinding::QuicUdpBinding ()
  : m_budpSocket (0), // IPv4 UDP 套接字指针，用于绑定 QUIC 到 IPv4 UDP, 初始值0 (空指针)
  m_budpSocket6 (0), // IPv6 UDP 套接字指针，用于绑定 QUIC 到 IPv6 UDP, 初始值0 (空指针)
  m_quicSocket (nullptr), // 指向当前绑定的 QUIC Socket 对象, 初始值nullptr
  m_listenerBinding (false), // 标记是否为监听状态下的绑定（如服务器端）, 初始值false
  m_pathId(0) // 路径 ID (初始值0)，用于多路径 QUIC（Multipath QUIC）中标识不同路径
{
  NS_LOG_FUNCTION (this); // 使用 NS_LOG_FUNCTION 记录构造过程，便于调试
}

// QuicUdpBinding 类的析构函数, 用于清理和释放资源, zhiy zeng
QuicUdpBinding::~QuicUdpBinding ()
{
  NS_LOG_FUNCTION (this);
  m_budpSocket = 0;
  m_budpSocket6 = 0;
  m_quicSocket = nullptr;
  m_listenerBinding = false;
  m_pathId = 0;
}

/*
作用：NS-3 中每个继承自 Object 的类都必须实现的标准方法之一。
返回该类的唯一类型标识符（TypeId）。它的主要职责包括：
* 注册类的元信息（如父类、构造函数、属性等）；
* 使类可以被 NS-3 的对象工厂创建；
* 允许类的成员变量作为“属性”暴露给用户脚本或配置系统；
* 支持运行时类型识别与转换（RTTI-like behavior）；

返回值：
返回一个 TypeId 对象，用于在 NS-3 中唯一标识 QuicUdpBinding 类型。

zhiy zeng
*/
TypeId
QuicUdpBinding::GetTypeId (void)
{
  // 创建一个静态局部变量 tid，表示当前类的类型 ID
  // 名称空间为 ns3::，类名为 QuicUdpBinding
  static TypeId tid = TypeId ("ns3::QuicUdpBinding")
    .SetParent<Object> () // QuicUdpBinding 继承自 ns3::Object, 
    // 所有 NS-3 协议组件都直接或间接继承自 Object
    .SetGroupName ("Internet") // 将该类归入 "Internet" 模块组
    .AddConstructor<QuicUdpBinding> () // 注册构造函数, 允许 NS-3 的对象
    // 工厂通过此构造函数动态创建 QuicUdpBinding 实例
    // 添加属性 "QuicSocketBase"，用于绑定 QUIC 套接字
    // 该属性的默认值为 nullptr，表示未绑定 QUIC 套接字
    // MakePointerAccessor绑定到成员变量 m_quicSocket
    // MakePointerChecker 用于检查指针类型是否为 QuicSocketBase
    .AddAttribute ("QuicSocketBase", "The QuicSocketBase pointer.",
                   PointerValue (),
                   MakePointerAccessor (&QuicUdpBinding::m_quicSocket),
                   MakePointerChecker<QuicSocketBase> ())
  ;
  //NS_LOG_UNCOND("QuicUdpBinding");
  return tid; // 返回类型 ID
}

/*
作用：返回当前对象的类型 ID。

zhiy zeng
*/
TypeId
QuicUdpBinding::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}



#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT                                   \
  if (m_node) { std::clog << " [node " << m_node->GetId () << "] "; }

/* see http://www.iana.org/assignments/protocol-numbers */
const uint8_t QuicL4Protocol::PROT_NUMBER = 143;

/*
作用：返回 QuicL4Protocol 类型的唯一标识符；
GetTypeId() 是 NS-3 中每个继承自 Object 的
类都必须实现的标准方法之一。它的主要职责包括：
  * 注册类的元信息（如父类、组名、构造函数）；
  * 将类的关键成员变量暴露为“属性”，便于用户脚本或配置系统进行设置；
  * 支持运行时类型识别与对象创建；
  * 实现模块化组织（如归入 "Internet" 组）；

返回值：
返回一个 TypeId 对象，用于在 NS-3 中唯一标识该类并支持反射、配置等功能。

zhiy zeng
*/
TypeId
QuicL4Protocol::GetTypeId (void)
{
  // 创建一个静态局部变量 tid，表示当前类的类型 ID
  // 名称空间为 ns3::，类名为 QuicL4Protocol
  static TypeId tid = TypeId ("ns3::QuicL4Protocol")
    .SetParent<IpL4Protocol> () // QuicL4Protocol 继承自 IpL4Protocol
    // IpL4Protocol 是 NS-3 中的一个类，表示 IP 协议栈的第四层协议 (TCP/UDP/QUIC)
    .SetGroupName ("Internet") // 将该类归入 "Internet" 模块组
    .AddConstructor<QuicL4Protocol> () // 注册构造函数, 允许 NS-3 的对象
    // 工厂通过此构造函数动态创建 QuicL4Protocol 实例

    // 添加属性：RTT 估计器类型，允许用户选择不同的 RTT 估计算法（如 EWMA、Min 等）
    .AddAttribute ("RttEstimatorType", // 属性名
                   "Type of RttEstimator objects.", // 描述
                   TypeIdValue (RttMeanDeviation::GetTypeId ()), // 默认值
                   // 绑定到成员变量 m_rttTypeId
                   MakeTypeIdAccessor (&QuicL4Protocol::m_rttTypeId), 
                   MakeTypeIdChecker ())
    // 添加属性：是否启用 0-RTT 握手，控制 QUIC 是否尝试使用 0-RTT 数据发送功能
    .AddAttribute ("0RTT-Handshake", "0RTT-Handshake start",
                   BooleanValue (false),
                   // 绑定到成员变量 m_0RTTHandshakeStart
                   MakeBooleanAccessor (&QuicL4Protocol::m_0RTTHandshakeStart),
                   MakeBooleanChecker ())
    // 添加属性：拥塞控制算法类型, 允许用户选择不同拥塞控制算法（如 Reno、Cubic、BBR 等）
    .AddAttribute ("SocketType",
                   "Socket type of QUIC objects.",
                   TypeIdValue (QuicCongestionOps::GetTypeId ()),
                   // 绑定到成员变量 m_congestionTypeId
                   // 该成员变量用于存储拥塞控制算法的类型 ID
                   MakeTypeIdAccessor (&QuicL4Protocol::m_congestionTypeId),
                   MakeTypeIdChecker ())
    // 添加属性：绑定到 UDP 的 QUIC 套接字列表, 管理多个 UDP 套接字与 QUIC 协议之间的绑定关系
    .AddAttribute ("SocketList", "The list of UDP and QUIC sockets associated to this protocol.",
                   ObjectVectorValue (),
                   // 绑定到成员变量 m_quicUdpBindingList
                   MakeObjectVectorAccessor (&QuicL4Protocol::m_quicUdpBindingList),
                   MakeObjectVectorChecker<QuicUdpBinding> ())
    /*.AddAttribute ("AuthAddresses", "The list of Authenticated addresses associated to this protocol.",
                                           ObjectVectorValue (),
                                           MakeObjectVectorAccessor (&QuicL4Protocol::m_authAddresses),
                                           MakeObjectVectorChecker<Address> ())*/
  ;
  return tid;
}

/*
作用：初始化 QuicL4Protocol 对象, 设置协议对象的基本成员变量，
并为后续绑定 UDP 套接字、处理连接端点等操作做好准备;

zhiy zeng
*/
QuicL4Protocol::QuicL4Protocol ()
  : m_node (0), // 初始值0, 当前协议所属节点的 ID
  m_0RTTHandshakeStart (false), // 初始值false, 是否启用 0-RTT 握手
  m_isServer (false), // 初始值false, 是否为服务器端
  m_endPoints (new Ipv4EndPointDemux ()), // 初始值为新建的 IPv4 端点解复用器
  // 用于管理 IPv4 上的连接端点（如本地/远程地址和端口）
  m_endPoints6 (new Ipv6EndPointDemux ())
{
  NS_LOG_FUNCTION_NOARGS ();
  NS_LOG_LOGIC ("Created QuicL4Protocol object " << this);
  // 初始化 QUIC UDP 绑定列表, 初始化 m_quicUdpBindingList 
  // 成员为一个空的 ObjectVector<QuicUdpBinding>
  m_quicUdpBindingList = QuicUdpBindingList ();
}

// QuicL4Protocol 类的析构函数, 用于释放类实例在生命周期内分配的资源,
// 以及清理和关闭与 QUIC 协议相关的所有 UDP 套接字和端点解复用器, zhiy zeng
QuicL4Protocol::~QuicL4Protocol ()
{
  NS_LOG_FUNCTION (this);
  m_quicUdpBindingList.clear ();
}

/*
作用：设置该协议所属的 Node；

参数说明：
node：指向 NS-3 中的 Node 对象，通常代表一个主机或路由器；

返回值：
void，即不返回任何值。

zhiy zeng
*/
void
QuicL4Protocol::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_FUNCTION (this << node);

  m_node = node; // 将传入的 node 赋值给类成员变量 m_node
}

/*
作用：为指定的 QUIC 套接字分配并绑定一个新的 UDP 套接字；

参数说明：
socket：指向 QuicSocketBase 的智能指针，表示要绑定 UDP 的 QUIC 套接字；

返回值：
成功时返回 0（Bind() 返回值），失败时返回 -1；
NS-3 中 Socket::Bind() 成功通常返回 0。

zhiy zeng
*/
int
QuicL4Protocol::UdpBind (Ptr<QuicSocketBase> socket)
{
  NS_LOG_FUNCTION (this << socket);
// std::cout<<"-------------QuicL4Protocol::UdpBind"<<std::endl;
  int res = -1;
  QuicUdpBindingList::iterator it;
  // 遍历协议维护的所有 QuicUdpBinding 对象，查找与传入的 QUIC 套接字匹配的项
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      // 如果找到匹配的 QUIC 套接字且其 UDP 套接字为空，则创建新的 UDP 套接字
      // 确保每个 QUIC 套接字只绑定一次 UDP 套接字
      if (item->m_quicSocket == socket and item->m_budpSocket == nullptr)
        {
          // 创建并绑定 UDP 套接字
          Ptr<Socket> udpSocket = CreateUdpSocket ();
          res = udpSocket->Bind ();
          item->m_budpSocket = udpSocket;
          break;
        }
    }

  return res; // 返回绑定结果
}

/*
同上，绑定 IPv6 套接字
作用：为指定的 QUIC 套接字分配并绑定一个新的 IPv6 UDP 套接字；

zhiy zeng
*/
int
QuicL4Protocol::UdpBind6 (Ptr<QuicSocketBase> socket)
{
  NS_LOG_FUNCTION (this << socket);

  int res = -1;
  QuicUdpBindingList::iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == socket and item->m_budpSocket6 == nullptr)
        {
          Ptr<Socket> udpSocket6 = CreateUdpSocket6 ();
          res = udpSocket6->Bind ();
          item->m_budpSocket6 = udpSocket6;
          break;
        }
    }

  return res;
}

/*
QuicL4Protocol 类中 重载的 UdpBind() 函数, 允许为 QUIC 套
接字绑定一个 UDP 套接字，并指定绑定的地址（IPv4 或 IPv6）

作用：根据给定地址为指定 QUIC 套接字绑定 UDP 套接字；

参数说明：
address：要绑定的目标地址（可以是 IPv4 或 IPv6）；
socket：指向 QuicSocketBase 的智能指针，表示当前 QUIC 套接字；

返回值：
成功时返回 0（Socket::Bind() 返回值）；
失败或未找到匹配项则返回 -1；

zhiy zeng
*/
int
QuicL4Protocol::UdpBind (const Address &address, Ptr<QuicSocketBase> socket)
{
  NS_LOG_FUNCTION (this << address << socket);

  int res = -1;
  // 检查地址是否为 IPv4 地址
  if (InetSocketAddress::IsMatchingType (address))
    {
      // 如果是 IPv4 地址，则遍历协议维护的所有 QuicUdpBinding 对象
      QuicUdpBindingList::iterator it;
      for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
        {
          Ptr<QuicUdpBinding> item = *it;
          // 寻找 m_quicSocket == socket && m_budpSocket == nullptr 的条目
          // 表示这个 QUIC 套接字还未绑定 IPv4 UDP 套接字
          if (item->m_quicSocket == socket and  item->m_budpSocket == nullptr)
            {
              // 创建 UDP 套接字
              Ptr<Socket> udpSocket = CreateUdpSocket ();
              // 调用 Bind(address) 显式绑定到指定地址
              res = udpSocket->Bind (address);
              // 将绑定的 UDP 套接字存储在 QuicUdpBinding 对象中
              item->m_budpSocket = udpSocket;
              break;
            }
        }

      return res;
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      QuicUdpBindingList::iterator it;
      for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
        {
          Ptr<QuicUdpBinding> item = *it;
          if (item->m_quicSocket == socket and item->m_budpSocket6 == nullptr)
            {
              Ptr<Socket> udpSocket6 = CreateUdpSocket ();
              res = udpSocket6->Bind (address);
              item->m_budpSocket6 = udpSocket6;
              break;
            }
        }

      return res;
    }
  return -1;
}

/*
作用：为 QUIC 套接字绑定并连接到指定地址的 UDP 套接字；

参数说明：
address：要连接的目标地址（可以是 IPv4 或 IPv6）；
socket：指向 QuicSocketBase 的智能指针，表示当前 QUIC 套接字；

返回值：
成功时返回 0（Socket::Connect() 返回值）；
失败或未找到匹配项则返回 -1；

zhiy zeng
*/
int
QuicL4Protocol::UdpConnect (const Address & address, Ptr<QuicSocketBase> socket)
{
  NS_LOG_FUNCTION (this << address << socket);
  // 检查地址是否为 IPv4 地址
  if (InetSocketAddress::IsMatchingType (address) == true)
    {
      // 绑定UDP 套接字, 确保当前 QUIC 套接字已经绑定了一个UDP 套接字
      UdpBind (address, socket);

      // 查找绑定条目并连接
      QuicUdpBindingList::iterator it;
      // 遍历列表查找匹配的 QUIC 套接字
      for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
        {
          Ptr<QuicUdpBinding> item = *it;
          if (item->m_quicSocket == socket)
            {
              // 调用 Connect(address) 与目标地址建立连接
              return item->m_budpSocket->Connect (address);
            }
        }

      NS_LOG_INFO ("UDP Socket: Connecting");

    }
  else if (Inet6SocketAddress::IsMatchingType (address) == true)
    {
      UdpBind (address, socket);

      QuicUdpBindingList::iterator it;
      for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
        {
          Ptr<QuicUdpBinding> item = *it;
          if (item->m_quicSocket == socket)
            {
              return item->m_budpSocket6->Connect (address);
            }
        }
      NS_LOG_INFO ("UDP Socket: Connecting");

    }
  NS_LOG_WARN ("UDP Connection Failed");
  return -1;
}

/*
作用：使用指定的 UDP 套接字发送一个QUIC包；

参数说明：
udpSocket：要使用的 UDP 套接字（IPv4 或 IPv6）；
p：要发送的数据包（NS-3 的 Packet 对象）；
flags：发送标志（如非阻塞等，通常传 0）；

返回值：
成功时返回 0；
失败时返回负值（错误码）；

zhiy zeng
*/
int
QuicL4Protocol::UdpSend (Ptr<Socket> udpSocket, Ptr<Packet> p, uint32_t flags) const
{
  NS_LOG_FUNCTION (this << udpSocket);

  return udpSocket->Send (p, flags);
}

/**
 * 作用: 从底层的 UDP 套接字接收数据包, 封装了 NS-3 框架中 Socket::RecvFrom() 
 * 方法的功能
 * 
 * 参数说明：
    udpSocket: 使用的 UDP 套接字（IPv4 或 IPv6），用于接收数据。
    maxSize: 接收缓冲区的最大大小，限制单次接收的数据量。
    flags: 用于接收操作的标志位（例如非阻塞模式）。
    address: 引用参数，用于存储发送方的地址信息。

  * 返回值:
    成功时返回一个包含收到数据的 Ptr<Packet> 对象；
    如果没有可用的数据或者发生错误，则可能返回空指针或根据具体实现返回错误码。
  
  zhiy zeng
 */
Ptr<Packet>
QuicL4Protocol::UdpRecv (Ptr<Socket> udpSocket, uint32_t maxSize, uint32_t flags, Address &address)
{
  NS_LOG_FUNCTION (this);

  return udpSocket->RecvFrom (maxSize, flags, address);
}

/**
 * 作用：查询当前绑定的 UDP 套接字的可用发送缓冲区大小；
 * 参数说明：
    quicSocket：指向 QuicSocketBase 的智能指针，表示当前要查询的 QUIC 套接字；
 * 返回值：
    成功时返回 item->m_budpSocket->GetTxAvailable()，即 UDP 套接字最多可发送
    的数据量（字节数）；
    如果未找到匹配项或 UDP 套接字为空，则返回 0

  zhiy zeng
 */
uint32_t
QuicL4Protocol::GetTxAvailable (Ptr<QuicSocketBase> quicSocket) const
{
  NS_LOG_FUNCTION (this);
// std::cout<<"####QuicL4Protocol::GetTxAvailable()#####"<<std::endl;
  QuicUdpBindingList::const_iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == quicSocket)
        {
          return item->m_budpSocket->GetTxAvailable ();
        }
    }
  return 0;
}

/**
 * 作用：查询当前绑定的 UDP 套接字的可用接收缓冲区大小；
 * 
 * 参数说明：
    quicSocket：指向 QuicSocketBase 的智能指针，表示当前要查询的 QUIC 套接字；
 * 返回值：
    成功时返回 item->m_budpSocket->GetRxAvailable()，即 UDP 套接字最多
    可读取的数据量（字节数）；
    如果未找到匹配项或 UDP 套接字为空，则返回 0；
  
  zhiy zeng
 */
uint32_t
QuicL4Protocol::GetRxAvailable (Ptr<QuicSocketBase> quicSocket) const
{
  NS_LOG_FUNCTION (this);

  QuicUdpBindingList::const_iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == quicSocket)
        {
          return item->m_budpSocket->GetRxAvailable ();
        }
    }
  return 0;
}

/**
 * 作用：查询当前 QUIC 套接字绑定的 UDP 套接字的本地地址；

 * 参数说明：
    quicSocket：指向 QuicSocketBase 的指针，表示当前要查询的 QUIC 套接字；
    address：输出参数，用于返回 UDP 套接字的本地地址信息；
 * 返回值：
    成功时返回 0；
    失败或未找到匹配项则返回 -1；
 
  zhiy zeng
 */
int
QuicL4Protocol::GetSockName (const ns3::QuicSocketBase* quicSocket, Address &address) const
{
  NS_LOG_FUNCTION (this);
  QuicUdpBindingList::const_iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == quicSocket)
        {
          return item->m_budpSocket->GetSockName (address);
        }
    }

  return -1;
}

/**
 * 作用：查询当前 QUIC 套接字绑定的 UDP 套接字的远端地址；
 
 * 参数说明：
  quicSocket：指向 QuicSocketBase 的指针，表示当前要查询的 QUIC 套接字；
  address：输出参数，用于返回 UDP 套接字的远端地址信息；

 * 返回值：
  成功时返回 0；
  失败或未找到匹配项则返回 -1；

zhiy zeng
 */
int
QuicL4Protocol::GetPeerName (const ns3::QuicSocketBase* quicSocket, Address &address) const
{
  NS_LOG_FUNCTION (this);

  QuicUdpBindingList::const_iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == quicSocket)
        {
          return item->m_budpSocket->GetPeerName (address);
        }
    }

  return -1;
}

/**
 * 作用：将底层 UDP 套接字绑定到指定的网络设备；

 * 参数说明：
    quicSocket：要操作的 QUIC 套接字；
    netdevice：目标网络设备（如 Wi-Fi、以太网等）；
 * 返回值：无（void）；
 * 
 * zhiy zeng
 */
void
QuicL4Protocol::BindToNetDevice (Ptr<QuicSocketBase> quicSocket, Ptr<NetDevice> netdevice)
{
  NS_LOG_FUNCTION (this);
  QuicUdpBindingList::iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == quicSocket)
        {
          item->m_budpSocket->BindToNetDevice (netdevice);
        }
    }
}

/**
 * 作用：将指定的 QUIC 套接字设置为监听状态；
 * 参数说明：
  sock：指向 QuicSocketBase 的智能指针，表示要设置为监听者的 QUIC 套接字；
 * 返回值：
  成功时返回 true；
  失败时返回 false；
 * zhiy zeng
 */
bool
QuicL4Protocol::SetListener (Ptr<QuicSocketBase> sock)
{
  NS_LOG_FUNCTION (this);

  if (sock != nullptr and m_quicUdpBindingList.size () == 1)
    {
      m_isServer = true;
      m_quicUdpBindingList.front ()->m_quicSocket = sock;
      m_quicUdpBindingList.front ()->m_listenerBinding = true;
      return true;
    }

  return false;
}

/**
 * 作用：判断当前 QUIC 协议实例是否为服务器；
 * 参数说明：无；
 * 返回值：
  true 表示是服务器；
  false 表示是客户端或其他角色；
 * zhiy zeng
 */
bool
QuicL4Protocol::IsServer (void)  const
{
  return m_isServer;
}

/**
 * 作用：获取当前协议中允许连接的已认证地址列表；
 * 参数说明：无；
 * 返回值：
  返回对 std::vector<Address> 的常量引用；
  外部不能修改该列表内容（因为是 const 引用）；
 * zhiy zeng 
 */
const std::vector<Address>&
QuicL4Protocol::GetAuthAddresses () const
{
  return m_authAddresses;
}

/**
 * 作用：将从 UDP 套接字接收到的数据包转发给对应的 QUIC 套接字；
 * 参数说明：
  sock：底层 UDP 套接字，用于接收数据包；
 * 返回值：无（void）；
 * zhiy zeng
 */
void
QuicL4Protocol::ForwardUp (Ptr<Socket> sock)
{
  NS_LOG_FUNCTION (this);
  Address from;
  Ptr<Packet> packet;

  while ((packet = sock->RecvFrom (from)))
    {
      NS_LOG_INFO ("Receiving packet on UDP socket");

      QuicHeader header;
      packet->RemoveHeader (header);
      NS_LOG_INFO(" Recv pkt " << header.GetPacketNumber () 
                <<" pathId: "<<header.GetPathId());
      //  std::cout<<this<< " Recv pkt " << header.GetPacketNumber () 
      //           <<" pathId: "<<header.GetPathId()
      //           << " recv seq " << header.GetSeq () 
      //           << " data size " << packet->GetSize () 
      //           <<"\n";

      // if (IsServer()){
      //   std::cout<<"recv\t"
      //           << (int)header.GetPathId() <<"\t"
      //           << header.GetPacketNumber () <<"\t"
      //           << Simulator::Now().GetSeconds()<< std::endl;
      // }

      uint64_t connectionId;
      if (header.HasConnectionId ())
        {
          connectionId = header.GetConnectionId ();
        }
      /*else if (m_sockets.size () <= 2) // Rivedere
        {
          if (m_sockets[0]->GetSocketState () != QuicSocket::LISTENING)
            {
              connectionId = m_sockets[0]->GetConnectionId ();
            }
          else if (m_sockets.size () == 2 && m_sockets[1]->GetSocketState () != QuicSocket::LISTENING)
            {
              connectionId = m_sockets[1]->GetConnectionId ();
            }
          else
            {
              NS_FATAL_ERROR ("The Connection ID can only be omitted by means of m_omit_connection_id transport parameter"
                              " if source and destination IP address and port are sufficient to identify a connection");
            }

        }*/
      else
        {
          NS_FATAL_ERROR ("The Connection ID can only be omitted by means of m_omit_connection_id transport parameter"
                          " if source and destination IP address and port are sufficient to identify a connection");
        }

      QuicUdpBindingList::iterator it;
      Ptr<QuicSocketBase> socket;
      for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
        {
          Ptr<QuicUdpBinding> item = *it;
          if (item->m_quicSocket->GetConnectionId () == connectionId)
            {
              socket = item->m_quicSocket;
              break;
            }
        }

      NS_LOG_LOGIC ((socket == nullptr));
      /*NS_LOG_INFO ("Initial " << header.IsInitial ());
      NS_LOG_INFO ("Handshake " << header.IsHandshake ());
      NS_LOG_INFO ("Short " << header.IsShort ());
      NS_LOG_INFO ("Version Negotiation " << header.IsVersionNegotiation ());
      NS_LOG_INFO ("Retry " << header.IsRetry ());
      NS_LOG_INFO ("0Rtt " << header.IsORTT ());*/

      if (header.IsInitial () and m_isServer and socket == nullptr)
        {
          NS_LOG_LOGIC (this << " Cloning listening socket " << m_quicUdpBindingList.front ()->m_quicSocket);
          socket = CloneSocket (m_quicUdpBindingList.front ()->m_quicSocket);
          socket->SetConnectionId (connectionId);
          socket->Connect (from);
          socket->SetupCallback ();

        }
      else if (header.IsHandshake () and m_isServer and socket != nullptr)
        {
          NS_LOG_LOGIC ("CONNECTION AUTHENTICATED - Server authenticated Client " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                        InetSocketAddress::ConvertFrom (from).GetPort () << "");
          m_authAddresses.push_back (InetSocketAddress::ConvertFrom (from).GetIpv4 ()); //add to the list of authenticated sockets
        }
      else if (header.IsHandshake () and !m_isServer and socket != nullptr)
        {
          NS_LOG_LOGIC ("CONNECTION AUTHENTICATED - Client authenticated Server " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                        InetSocketAddress::ConvertFrom (from).GetPort () << "");
          m_authAddresses.push_back (InetSocketAddress::ConvertFrom (from).GetIpv4 ()); //add to the list of authenticated sockets
        }
      else if (header.IsORTT () and m_isServer)
        {
          auto result = std::find (m_authAddresses.begin (), m_authAddresses.end (), InetSocketAddress::ConvertFrom (from).GetIpv4 ());
          // check if a 0-RTT is allowed with this endpoint - or if the attribute m_0RTTHandshakeStart has been forced to be true
          if (result == m_authAddresses.end () && m_0RTTHandshakeStart)
            {
              m_authAddresses.push_back (InetSocketAddress::ConvertFrom (from).GetIpv4 ()); //add to the list of authenticated sockets
            }
          else if (result == m_authAddresses.end () && !m_0RTTHandshakeStart)
            {
              NS_LOG_WARN ( this << " CONNECTION ABORTED: 0RTT Packet from unauthenticated address " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                            InetSocketAddress::ConvertFrom (from).GetPort ());
              continue;
            }

          NS_LOG_LOGIC ("CONNECTION AUTHENTICATED - Server authenticated Client " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                        InetSocketAddress::ConvertFrom (from).GetPort () << "");
          NS_LOG_LOGIC ( this << " Cloning listening socket " << m_quicUdpBindingList.front ()->m_quicSocket);
          socket = CloneSocket (m_quicUdpBindingList.front ()->m_quicSocket);
          socket->SetConnectionId (connectionId);
          socket->Connect (from);
          socket->SetupCallback ();

        }
      else if (header.IsShort ())
        {
          auto result = std::find (m_authAddresses.begin (), m_authAddresses.end (), InetSocketAddress::ConvertFrom (from).GetIpv4 ());

          if (result == m_authAddresses.end () && m_0RTTHandshakeStart)
            {
              m_authAddresses.push_back (InetSocketAddress::ConvertFrom (from).GetIpv4 ()); //add to the list of authenticated sockets
            }
          else if (result == m_authAddresses.end () && !m_0RTTHandshakeStart)
            {
              NS_LOG_WARN ( this << " CONNECTION ABORTED: Short Packet from unauthenticated address " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                            InetSocketAddress::ConvertFrom (from).GetPort ());
              continue;
            }
        }

      // Handle callback for the correct socket
      if (!m_socketHandlers[socket].IsNull ())
        {
          NS_LOG_LOGIC (this << " waking up handler of socket " << socket);
          m_socketHandlers[socket] (packet, header, from);
        }
      else
        {
          NS_FATAL_ERROR ( this << " no handler for socket " << socket);
        }
    }
}

/**
 * 作用：
    为指定的 QUIC 套接字注册接收数据包的回调；
    将底层 UDP 套接字的接收事件绑定到 ForwardUp()；
 * 参数说明：
    handler：用户定义的回调函数，用于处理解析后的 QUIC 数据包；
    sock：要绑定回调的 QUIC 套接字；
 * 返回值：无（void）；
 * zhiy zeng
 */
void
QuicL4Protocol::SetRecvCallback (Callback<void, Ptr<Packet>, const QuicHeader&,  Address& > handler, Ptr<Socket> sock)
{

  NS_LOG_FUNCTION (this);

  m_socketHandlers.insert ( std::pair< Ptr<Socket>, Callback<void, Ptr<Packet>, const QuicHeader&, Address& > > (sock,handler));
  QuicUdpBindingList::iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == sock && item->m_budpSocket != 0)
        {
          item->m_budpSocket->SetRecvCallback (MakeCallback (&QuicL4Protocol::ForwardUp, this));
          break;
        }
      else if (item->m_quicSocket == sock && item->m_budpSocket6 != 0)
        {
          item->m_budpSocket6->SetRecvCallback (MakeCallback (&QuicL4Protocol::ForwardUp, this));
          break;
        }
      else if (item->m_quicSocket == sock)
        {
          NS_FATAL_ERROR ("The UDP socket for this QuicUdpBinding item is not set");
        }
    }
}

/**
 * 作用：当该协议实例被聚合到某个 Node 时进行初始化；
 * 参数说明：无；
 * 返回值：无（void）；
 * zhiy zeng
 */
void
QuicL4Protocol::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this);
  Ptr<Node> node = this->GetObject<Node> ();

  if (m_node == 0)
    {
      if ((node != 0))
        {
          this->SetNode (node);
          Ptr<QuicSocketFactory> quicFactory = CreateObject<QuicSocketFactory> ();
          quicFactory->SetQuicL4 (this);
          node->AggregateObject (quicFactory);
        }
    }

  IpL4Protocol::NotifyNewAggregate ();
}

/**
 * 作用：获取当前协议的协议号；
 * 参数说明：无；
 * 返回值：
  返回协议号，通常是一个整数值；
  在 QUIC 协议中，协议号通常是一个常量（如 0x51）；
 * zhiy zeng
 */
int
QuicL4Protocol::GetProtocolNumber (void) const
{
  return PROT_NUMBER;
}

/**
 * 作用：释放该 QUIC 协议实例所占用的资源；
 * 参数说明：无；
 * 返回值：无（void）；
 * zhiy zeng
 */
void
QuicL4Protocol::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_quicUdpBindingList.clear ();

  m_node = 0;
//  m_downTarget.Nullify ();
//  m_downTarget6.Nullify ();
  IpL4Protocol::DoDispose ();
}

/**
 * 作用：克隆一个 QUIC 套接字，并建立新的绑定关系；
 * 参数说明：
    oldsock：要克隆的原始 QUIC 套接字（通常是一个监听套接字）；
 * 返回值：新创建的 QuicSocketBase 智能指针；
 * zhiy zeng
 */
Ptr<QuicSocketBase>
QuicL4Protocol::CloneSocket (Ptr<QuicSocketBase> oldsock)
{
  NS_LOG_FUNCTION (this);
  Ptr<QuicSocketBase> newsock = CopyObject<QuicSocketBase> (oldsock);
  NS_LOG_LOGIC (this << " cloned socket " << oldsock << " to socket " << newsock);
  Ptr<QuicUdpBinding> udpBinding = CreateObject<QuicUdpBinding> ();
  udpBinding->m_budpSocket = nullptr;
  udpBinding->m_budpSocket6 = nullptr;
  udpBinding->m_quicSocket = newsock;
  udpBinding->m_pathId = 0;
  m_quicUdpBindingList.insert (m_quicUdpBindingList.end (), udpBinding);

  return newsock;
}

/**
 * 作用：创建一个 QUIC 套接字实例；
 * 参数说明：无；
 * 返回值：指向新创建的 Socket 的智能指针（实际类型应为 QuicSocketBase 或其子类）；
 */
Ptr<Socket>
QuicL4Protocol::CreateSocket ()
{
  return CreateSocket (m_congestionTypeId);
}

/**
 * 作用：创建一个具有指定拥塞控制算法的 QUIC 套接字；
 * 参数说明：
    congestionTypeId：拥塞控制算法类型（如 ns3::TcpNewReno, ns3::TcpCubic, 
    或自定义的 QuicCubic）；
 * 返回值：指向新创建的 Socket 的智能指针（实际为 QuicSocketBase 类型）；
 * zhiy zeng
 */
Ptr<Socket>
QuicL4Protocol::CreateSocket (TypeId congestionTypeId)
{
  NS_LOG_FUNCTION (this);
  ObjectFactory congestionAlgorithmFactory;
  congestionAlgorithmFactory.SetTypeId (m_congestionTypeId);

  // create the socket
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  // create the congestion control algorithm
  Ptr<TcpCongestionOps> algo = congestionAlgorithmFactory.Create<TcpCongestionOps> ();
  socket->SetCongestionControlAlgorithm (algo);

  // TODO consider if rttFactory is needed
  // Ptr<RttEstimator> rtt = rttFactory.Create<RttEstimator> ();
  // socket->SetRtt (rtt);

  socket->SetNode (m_node);
  socket->SetQuicL4 (this);

  socket->InitializeScheduling ();

  // generate a random connection ID and check that has not been assigned to other
  // sockets associated to this L4 protocol
  Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();

  bool found = false;
  uint64_t connectionId;
  while (not found)
    {
      connectionId = uint64_t (rand->GetValue (0, pow (2, 64) - 1));
      found = true;
      for (auto it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
        {
          found = false;
          if (connectionId == (*it)->m_quicSocket->GetConnectionId ())
            {
              break;
            }
          found = true;
        }
    }
  socket->SetConnectionId (connectionId);
  Ptr<QuicUdpBinding> udpBinding = Create<QuicUdpBinding> ();
  udpBinding->m_budpSocket = nullptr;
  udpBinding->m_budpSocket6 = nullptr;
  udpBinding->m_quicSocket = socket;
  udpBinding->m_pathId = 0;
  m_quicUdpBindingList.insert (m_quicUdpBindingList.end (), udpBinding);

  return socket;
}

/**
 * 作用：创建一个IPv4 UDP 套接字；
 * 参数说明：无；
 * 返回值：指向新创建的 Socket 的智能指针（实际类型为 UdpSocketImpl 或其子类）；
 */
Ptr<Socket>
QuicL4Protocol::CreateUdpSocket ()
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_node != 0);

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> udpSocket = Socket::CreateSocket (m_node, tid);

  return udpSocket;
}

Ptr<Socket>
QuicL4Protocol::CreateUdpSocket6 ()
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_node != 0);

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> udpSocket6 = Socket::CreateSocket (m_node, tid);

  return udpSocket6;
}

void
QuicL4Protocol::ReceiveIcmp (Ipv4Address icmpSource, uint8_t icmpTtl,
                             uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                             Ipv4Address payloadSource,Ipv4Address payloadDestination,
                             const uint8_t payload[8])
{
  NS_LOG_FUNCTION (this << icmpSource << (uint16_t) icmpTtl << (uint16_t) icmpType << (uint16_t) icmpCode << icmpInfo
                        << payloadSource << payloadDestination);
}

void
QuicL4Protocol::ReceiveIcmp (Ipv6Address icmpSource, uint8_t icmpTtl,
                             uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                             Ipv6Address payloadSource,Ipv6Address payloadDestination,
                             const uint8_t payload[8])
{
  NS_LOG_FUNCTION (this << icmpSource << (uint16_t) icmpTtl << (uint16_t) icmpType << (uint16_t) icmpCode << icmpInfo
                        << payloadSource << payloadDestination);

}

enum IpL4Protocol::RxStatus
QuicL4Protocol::Receive (Ptr<Packet> packet,
                         Ipv4Header const &incomingIpHeader,
                         Ptr<Ipv4Interface> incomingInterface)
{
  NS_LOG_FUNCTION (this << packet << incomingIpHeader << incomingInterface);
  NS_FATAL_ERROR ("This call should not be used: QUIC packets need to go through a UDP socket");
  return IpL4Protocol::RX_OK;
}

enum IpL4Protocol::RxStatus
QuicL4Protocol::Receive (Ptr<Packet> packet,
                         Ipv6Header const &incomingIpHeader,
                         Ptr<Ipv6Interface> interface)
{
  NS_LOG_FUNCTION (this << packet << incomingIpHeader.GetSourceAddress () <<
                   incomingIpHeader.GetDestinationAddress ());
  NS_FATAL_ERROR ("This call should not be used: QUIC packets need to go through a UDP socket");
  return IpL4Protocol::RX_OK;
}

void
QuicL4Protocol::SendPacket (Ptr<QuicSocketBase> socket, Ptr<Packet> pkt, const QuicHeader &outgoing) const
{
  NS_LOG_FUNCTION (this << socket);
  uint8_t pathId = outgoing.GetPathId (); 
  NS_LOG_LOGIC (this << "sendpacket with"
                << " path Id: "<< pathId
                << " sending pkt #" << outgoing.GetPacketNumber ()
                << " data size " << pkt->GetSize ());

  //log for experiment
  // if (!IsServer()){
  //   std::cout<<"send\t"
  //            << (int)pathId <<"\t"
  //            << outgoing.GetPacketNumber () <<"\t"
  //            << Simulator::Now().GetSeconds()<< std::endl;
  // }

  
  NS_LOG_INFO ("Sending Packet Through UDP Socket");

  // Given the presence of multiple subheaders in pkt,
  // we create a new packet, add the new QUIC header and
  // then add pkt as payload
  Ptr<Packet> packetSent = Create<Packet> ();
  packetSent->AddHeader (outgoing);
  packetSent->AddAtEnd (pkt);

  QuicUdpBindingList::const_iterator it;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_quicSocket == socket && item->m_pathId == pathId)
        {
          UdpSend (item->m_budpSocket, packetSent, 0);
          break;
        }
    }
}


bool
QuicL4Protocol::RemoveSocket (Ptr<QuicSocketBase> socket)
{
  NS_LOG_FUNCTION (this);

  QuicUdpBindingList::iterator iter;
  bool found = false;
  bool closedListener = false;

  for (iter = m_quicUdpBindingList.begin (); iter != m_quicUdpBindingList.end (); ++iter)
    {
      Ptr<QuicUdpBinding> item = *iter;
      if (item->m_quicSocket == socket)
        {
          found = true;
          if (item->m_listenerBinding)
            {
              closedListener = true;
            }
          m_quicUdpBindingList.erase (iter);

          break;
        }
    }

  //if closing the listener, close all the clone ones
  if (closedListener)
    {
      NS_LOG_LOGIC (this << " Closing all the cloned sockets");
      iter = m_quicUdpBindingList.begin ();
      while (iter != m_quicUdpBindingList.end ())
        {
          (*iter)->m_quicSocket->Close ();
          ++iter;
        }
    }

  return found;
}

Ipv4EndPoint *
QuicL4Protocol::Allocate (void)
{
  NS_LOG_FUNCTION (this);
  return m_endPoints->Allocate ();
}

Ipv4EndPoint *
QuicL4Protocol::Allocate (Ipv4Address address)
{
  NS_LOG_FUNCTION (this << address);
  return m_endPoints->Allocate (address);
}

Ipv4EndPoint *
QuicL4Protocol::Allocate (Ptr<NetDevice> boundNetDevice, uint16_t port)
{
  NS_LOG_FUNCTION (this << boundNetDevice << port);
  return m_endPoints->Allocate (boundNetDevice, port);
}

Ipv4EndPoint *
QuicL4Protocol::Allocate (Ptr<NetDevice> boundNetDevice, Ipv4Address address, uint16_t port)
{
  NS_LOG_FUNCTION (this << boundNetDevice << address << port);
  return m_endPoints->Allocate (boundNetDevice, address, port);
}

Ipv4EndPoint *
QuicL4Protocol::Allocate (Ptr<NetDevice> boundNetDevice,
                          Ipv4Address localAddress, uint16_t localPort,
                          Ipv4Address peerAddress, uint16_t peerPort)
{
  NS_LOG_FUNCTION (this << boundNetDevice << localAddress << localPort << peerAddress << peerPort);
  return m_endPoints->Allocate (boundNetDevice,
                                localAddress, localPort,
                                peerAddress, peerPort);
}

Ipv6EndPoint *
QuicL4Protocol::Allocate6 (void)
{
  NS_LOG_FUNCTION (this);
  return m_endPoints6->Allocate ();
}

Ipv6EndPoint *
QuicL4Protocol::Allocate6 (Ipv6Address address)
{
  NS_LOG_FUNCTION (this << address);
  return m_endPoints6->Allocate (address);
}

Ipv6EndPoint *
QuicL4Protocol::Allocate6 (Ptr<NetDevice> boundNetDevice, uint16_t port)
{
  NS_LOG_FUNCTION (this << boundNetDevice << port);
  return m_endPoints6->Allocate (boundNetDevice, port);
}

Ipv6EndPoint *
QuicL4Protocol::Allocate6 (Ptr<NetDevice> boundNetDevice, Ipv6Address address, uint16_t port)
{
  NS_LOG_FUNCTION (this << boundNetDevice << address << port);
  return m_endPoints6->Allocate (boundNetDevice, address, port);
}

Ipv6EndPoint *
QuicL4Protocol::Allocate6 (Ptr<NetDevice> boundNetDevice,
                           Ipv6Address localAddress, uint16_t localPort,
                           Ipv6Address peerAddress, uint16_t peerPort)
{
  NS_LOG_FUNCTION (this << boundNetDevice << localAddress << localPort << peerAddress << peerPort);
  return m_endPoints6->Allocate (boundNetDevice,
                                 localAddress, localPort,
                                 peerAddress, peerPort);
}

void
QuicL4Protocol::DeAllocate (Ipv4EndPoint *endPoint)
{
  NS_LOG_FUNCTION (this << endPoint);
  m_endPoints->DeAllocate (endPoint);
}

void
QuicL4Protocol::DeAllocate (Ipv6EndPoint *endPoint)
{
  NS_LOG_FUNCTION (this << endPoint);
  m_endPoints6->DeAllocate (endPoint);
}

void
QuicL4Protocol::SetDownTarget (IpL4Protocol::DownTargetCallback callback)
{
  NS_LOG_FUNCTION (this);
  m_downTarget = callback;
}

IpL4Protocol::DownTargetCallback
QuicL4Protocol::GetDownTarget (void) const
{
  NS_LOG_FUNCTION (this);
  return m_downTarget;
}

void
QuicL4Protocol::SetDownTarget6 (IpL4Protocol::DownTargetCallback6 callback)
{
  NS_LOG_FUNCTION (this);
  m_downTarget6 = callback;
}

IpL4Protocol::DownTargetCallback6
QuicL4Protocol::GetDownTarget6 (void) const
{
  return m_downTarget6;
}

bool
QuicL4Protocol::Is0RTTHandshakeAllowed () const
{
  return m_0RTTHandshakeStart;
}

//For multipath implementation

int
QuicL4Protocol::AddPath(uint8_t pathId, Ptr<QuicSocketBase> socket, Address localAddress, Address peerAddress)
{
  NS_LOG_FUNCTION (this);
  int res = -1;
  if (InetSocketAddress::IsMatchingType (localAddress))
    {
      Ptr<QuicUdpBinding> udpBinding = CreateObject<QuicUdpBinding> ();
      Ptr<Socket> udpSocket = CreateUdpSocket ();
      res = udpSocket->Bind (localAddress);
      udpSocket->Connect(peerAddress);
      udpSocket->SetRecvCallback (MakeCallback (&QuicL4Protocol::ForwardUp, this));
      udpBinding->m_budpSocket = udpSocket;
      udpBinding->m_budpSocket6 = nullptr;
      udpBinding->m_quicSocket = socket;
      udpBinding->m_pathId = pathId;
      m_quicUdpBindingList.insert(m_quicUdpBindingList.end (),udpBinding);
      return res;
    }
  else if (Inet6SocketAddress::IsMatchingType (localAddress))
    {
      Ptr<QuicUdpBinding> udpBinding = CreateObject<QuicUdpBinding> ();
      Ptr<Socket> udpSocket = CreateUdpSocket ();
      res = udpSocket->Bind (localAddress);
      udpSocket->Connect(peerAddress);
      udpSocket->SetRecvCallback (MakeCallback (&QuicL4Protocol::ForwardUp, this));
      udpBinding->m_budpSocket = nullptr;
      udpBinding->m_budpSocket6 = udpSocket;
      udpBinding->m_quicSocket = socket;
      udpBinding->m_pathId = pathId;
      m_quicUdpBindingList.insert(m_quicUdpBindingList.end (),udpBinding);
      return res;
    }
  return -1;
}

void
QuicL4Protocol::Allow0RTTHandshake (bool allow0RTT)
{
  m_0RTTHandshakeStart = allow0RTT;
}

int
QuicL4Protocol::ReDoUdpConnect(uint8_t pathId, Address peerAddress)
{
  QuicUdpBindingList::iterator it;
  Ptr<QuicSocketBase> socket;
  for (it = m_quicUdpBindingList.begin (); it != m_quicUdpBindingList.end (); ++it)
    {
      Ptr<QuicUdpBinding> item = *it;
      if (item->m_pathId == pathId)
        {
          return item->m_budpSocket->Connect(peerAddress);
        }
    }
    return -1;
}

} // namespace ns3


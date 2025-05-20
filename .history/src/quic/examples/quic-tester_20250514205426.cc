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
 *          Federico Chiariotti <whatever@blbl.it>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          
 */

 /*
 * Added by zhiy zeng
 * This example is a simple QUIC echo client/server application.
  * The client sends a message to the server and waits for the reply.
  * The server replies with the same message.
  * The client and server are running on different nodes.
 */

#include "ns3/core-module.h" // NS3 core module, zhiy zeng
#include "ns3/network-module.h" // NS3 network module, zhiy zeng
#include "ns3/internet-module.h" // NS3 internet module, zhiy zeng
#include "ns3/quic-module.h" // NS3 QUIC module, zhiy zeng
#include "ns3/point-to-point-module.h" // NS3 point-to-point module, zhiy zeng
#include "ns3/applications-module.h" // NS3 applications module, zhiy zeng
#include "ns3/config-store-module.h" // NS3 config store module, zhiy zeng
#include <iostream>

using namespace ns3; // Using the ns3 namespace, zhiy zeng

// Define the logging component for the QUIC tester, zhiy zeng
NS_LOG_COMPONENT_DEFINE("quic-tester");

int
main (int argc, char *argv[])
{
  CommandLine cmd;
  cmd.Parse (argc, argv);

  std::cout
      << "\n\n#################### SIMULATION SET-UP ####################\n\n\n";

  LogLevel log_precision = LOG_LEVEL_LOGIC;
  Time::SetResolution (Time::NS); // Set the time resolution to nanoseconds, zhiy zeng
  LogComponentEnableAll (LOG_PREFIX_TIME); // Enable time logging, zhiy zeng
  LogComponentEnableAll (LOG_PREFIX_FUNC); // Enable function logging, zhiy zeng
  LogComponentEnableAll (LOG_PREFIX_NODE); // Enable node logging, zhiy zeng
  // Enable QuicEchoClient and QuicEchoServer logging, zhiy zeng
  LogComponentEnable ("QuicEchoClientApplication", log_precision);
  LogComponentEnable ("QuicEchoServerApplication", log_precision);
//  LogComponentEnable ("QuicHeader", log_precision);
  //LogComponentEnable ("QuicSocketBase", log_precision);
//  LogComponentEnable ("QuicStreamBase", LOG_LEVEL_LOGIC);
//  LogComponentEnable ("Socket", log_precision);
//  LogComponentEnable ("Application", log_precision);
//  LogComponentEnable ("Node", log_precision);
//  LogComponentEnable ("InternetStackHelper", log_precision);
//  LogComponentEnable ("QuicSocketFactory", log_precision);
//  LogComponentEnable ("ObjectFactory", log_precision);
//  //LogComponentEnable ("TypeId", log_precision);
//  LogComponentEnable ("QuicL4Protocol", log_precision);
//  LogComponentEnable ("QuicL5Protocol", log_precision);
//  //LogComponentEnable ("ObjectBase", log_precision);
//
//  LogComponentEnable ("QuicEchoHelper", log_precision);
    LogComponentEnable ("QuicSocketTxScheduler", log_precision);
//  LogComponentEnable ("QuicSocketRxBuffer", log_precision);
//  LogComponentEnable ("QuicHeader", log_precision);
//  LogComponentEnable ("QuicSubheader", log_precision);
//  LogComponentEnable ("Header", log_precision);
//  LogComponentEnable ("PacketMetadata", log_precision);

  ////////////////////// Create nodes and link characteristics //////////////////////
  // Add by zhiy zeng
  NodeContainer nodes;
  nodes.Create (2);
  auto n1 = nodes.Get (0); // node n1, zhiy zeng
  auto n2 = nodes.Get (1); // node n2, zhiy zeng

  PointToPointHelper pointToPoint;
  // Bandwidth and delay of the link, 5Mbps and 2ms, respectively, zhiy zeng
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer devices;
  devices = pointToPoint.Install (nodes); // Install the point-to-point link between the nodes, zhiy zeng
  ////////////////////////// Create nodes and link characteristics //////////////////////

  QuicHelper stack;
  stack.InstallQuic (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  QuicEchoServerHelper echoServer (9);

  ApplicationContainer serverApps = echoServer.Install (nodes.Get (1));
  serverApps.Start (Seconds (1.0));
  serverApps.Stop (Seconds (1200.0));

  QuicEchoClientHelper echoClient (interfaces.GetAddress (1), 9);
  echoClient.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
  //echoClient.SetAttribute ("MaxStreamData", UintegerValue (1024));

  ApplicationContainer clientApps = echoClient.Install (nodes.Get (0));
  echoClient.SetFill (clientApps.Get (0), "Hello World");
  clientApps.Start (Seconds (2.0));
  clientApps.Stop (Seconds (5.0));

  Packet::EnablePrinting ();
  Packet::EnableChecking ();

  std::cout << "\n\n#################### STARTING RUN ####################\n\n";
  Simulator::Run ();
  std::cout
      << "\n\n#################### RUN FINISHED ####################\n\n\n";
  Simulator::Destroy ();

  std::cout
      << "\n\n#################### SIMULATION END ####################\n\n\n";
  return 0;
}

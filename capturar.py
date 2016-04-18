#! /usr/bin/python
 # -*- coding: utf-8 -*-

import os
import sys
import argparse
import socket
import signal
import math
from scapy import utils
from scapy.all import IP, sniff
from collections import defaultdict
from matplotlib import pyplot as ptl

PROTOCOL_MAPPINGS = {
    '0x800': "Internet Protocol version 4 (IPv4)",
    '0x806': "Address Resolution Protocol (ARP)",
    '0x842': "Wake-on-LAN[7]",
    '0x22f3': "IETF TRILL Protocol",
    '0x6003': "DECnet Phase IV",
    '0x8035': "Reverse Address Resolution Protocol",
    '0x809b': "AppleTalk (Ethertalk)",
    '0x80f3': "AppleTalk Address Resolution Protocol (AARP)",
    '0x8100': "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq[8]",
    '0x8137': "IPX",
    '0x8204': "QNX Qnet",
    '0x86dd': "Internet Protocol Version 6 (IPv6)",
    '0x8808': "Ethernet flow control",
    '0x8819': "CobraNet",
    '0x8847': "MPLS unicast",
    '0x8848': "MPLS multicast",
    '0x8863': "PPPoE Discovery Stage",
    '0x8864': "PPPoE Session Stage",
    '0x8870': "Jumbo Frames (proposed)[2][3]",
    '0x887b': "HomePlug 1.0 MME",
    '0x888e': "EAP over LAN (IEEE 802.1X)",
    '0x8892': "PROFINET Protocol",
    '0x889a': "HyperSCSI (SCSI over Ethernet)",
    '0x88a2': "ATA over Ethernet",
    '0x88a4': "EtherCAT Protocol",
    '0x88a8': "Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[9]",
    '0x88ab': "Ethernet Powerlink[citation needed]",
    '0x88cc': "Link Layer Discovery Protocol (LLDP)",
    '0x88cd': "SERCOS III",
    '0x88e1': "HomePlug AV MME[citation needed]",
    '0x88e3': "Media Redundancy Protocol (IEC62439-2)",
    '0x88e5': "MAC security (IEEE 802.1AE)",
    '0x88e7': "Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
    '0x88f7': "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)",
    '0x8902': "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)",
    '0x8906': "Fibre Channel over Ethernet (FCoE)",
    '0x8914': "FCoE Initialization Protocol",
    '0x8915': "RDMA over Converged Ethernet (RoCE)",
    '0x891d': "TTEthernet Protocol Control Frame (TTE)",
    '0x892f': "High-availability Seamless Redundancy (HSR)",
    '0x9000': "Ethernet Configuration Testing Protocol[10]",
}

def buscar_protocolo(tipo):
    try:
        return PROTOCOL_MAPPINGS[tipo]
    except KeyError:
        return tipo

class Run(object):
    def __init__(self, args):
        self.args = args
        self.offline = bool(args.pcap)
        self.total_paquetes = 0
        self.protocolos = defaultdict(int)
        self.entropia = 0
        self.pkts = list()

    def correr(self):
        args = self.args
        try:
            sniff(
                store=0, count=args.cantidad, iface=args.interface, 
                prn=self.procesar_paquete, filter=args.filtro,
                timeout=args.tiempo, offline=args.pcap
            )
        except socket.error:
            print u"No existe interface '{0}'".format(args.interface)
            sys.exit(2)
        self.finalizar()

    def procesar_paquete(self, pkt):
        try:
            tipo = buscar_protocolo(hex(pkt.type))
            if self.offline and self.args.filtro:
                if 'arp' in self.args.filtro and tipo != "Address Resolution Protocol (ARP)":
                    return
            self.total_paquetes += 1
            self.protocolos[tipo] += 1
            if self.args.salida:
                self.pkts.append(pkt)
            print pkt.summary()
        except Exception, e:
            print "Error obteniendo tipo ({0})".format(type(e))

    def finalizar(self):
        if self.total_paquetes:
            for key, value in self.protocolos.items():
                if value:
                    prob = float(value)/self.total_paquetes
                    self.entropia -= prob * math.log(prob, 2)
            if self.args.salida:
                utils.wrpcap(self.args.salida + ".pcap", self.pkts)

    def resultados(self):
        res = u"Total paquetes: {0}\n".format(self.total_paquetes)
        if self.total_paquetes:
            res += u"Protocolos:\n"
            for key, value in self.protocolos.items():
                res += u"\tProtocolo {0}: {1}\n".format(key, value)
            res += u"Entropía: {0}".format(self.entropia)
        return res

    def graficar(self):
        pass


def main(argv):
    parser = argparse.ArgumentParser(description='Capturador de paquetes')
    parser.add_argument(
        "--cantidad", "-c", type=int, default=0, 
        help=u"Cantidad de paquetes a capturar. 0 significa infinito."
    )
    parser.add_argument("--interface", "-i", type=str, default="eth0", 
        help=u"Interfaz de red a utilizar"
    )
    parser.add_argument(
        "--filtro", "-f", type=str, default=None, 
        help=u"Filtro de paquetes. Ver 'man pcap-filter' para sintaxis"
    )
    parser.add_argument(
        "--pcap", "-p", type=str, default=None, 
        help=u"Archivo .pcap"
    )
    parser.add_argument(
        "--salida", "-s", type=str, default=None, 
        help=u"Archivo de salida"
    )
    parser.add_argument(
        "--graficos", "-g", type=bool, default=False, 
        help=u"Plotear graficos"
    )
    parser.add_argument(
        "--tiempo", "-t", type=int, default=None, 
        help=u"Correr hasta tantos segundos"
    )
    args = parser.parse_args(argv[1:])
    run = Run(args)
    run.correr()
    print run.resultados()
    if args.graficos:
        run.graficar()

if __name__ == '__main__':
    try:
        if os.geteuid():
            print u"Tenés que correrlo con sudo"
            sys.exit(1) 
    except (OSError, AttributeError):
        pass
    main(sys.argv)

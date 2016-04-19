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
from capturar import buscar_protocolo

class Host(object):
    def __init__(self, mac_address):
        self.mac_address = mac_address
        self.ip = None

class Identificador(object):
    def __init__(self, args):
        self.args = args
        self.offline = bool(args.pcap)
        self.total_paquetes = 0
        self.entropia = 0
        self.pkts = list()
        self.contador = defaultdict(int)
        self.tabla_arp = dict()

    def correr(self):
        args = self.args
        try:
            sniff(
                store=0, count=args.cantidad, iface=args.interface, 
                prn=self.procesar_paquete, timeout=args.tiempo,
                lfilter=self.filtrar, offline=args.pcap
            )
        except socket.error:
            print u"No existe interface '{0}'".format(args.interface)
            sys.exit(2)
        self.finalizar()

    def procesar_paquete(self, pkt):
        try:
            print pkt.summary()
            eth_src = pkt.src
            eth_dst = pkt.dst
            arp_pkt = pkt["ARP"]
            mac_src = arp_pkt.hwsrc
            ip_src = arp_pkt.psrc
            self.tabla_arp[ip_src] = mac_src
            ip_dst = arp_pkt.pdst
            mac_dst = None
            if arp_pkt.op == "is-at":
                mac_dst = arp_pkt.hwdst
            self.contador[mac_src] += 1
            if mac_dst:
                self.contador[mac_dst] += 1 
            self.total_paquetes += 1
            if self.args.salida:
                self.pkts.append(pkt)
        except Exception, e:
            print "Error procesando paquete({0})".format(type(e))

    @staticmethod
    def filtrar(pkt):
        return "ARP" in pkt

    def finalizar(self):
        if self.total_paquetes and self.args.salida:
            utils.wrpcap(self.args.salida + ".pcap", self.pkts)

    def resultados(self):
        res = u"";
        for key, value in self.contador.items():
            res += u"{0}: {1}\n".format(key, value)
        print self.tabla_arp
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
    ident = Identificador(args)
    ident.correr()
    print ident.resultados()
    if args.graficos:
        ident.graficar()

if __name__ == '__main__':
    try:
        if os.geteuid():
            print u"Tenés que correrlo con sudo"
            sys.exit(1) 
    except (OSError, AttributeError):
        pass
    main(sys.argv)

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


class Run(object):
    def __init__(self, args):
        self.args = args
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
                offline=args.pcap
            )
        except socket.error:
            print u"No existe interface '{0}'".format(args.interface)
            sys.exit(2)
        self.finalizar()

    def procesar_paquete(self, pkt):
        print pkt.summary()
        try:
            tipo = hex(pkt.type)
            self.total_paquetes += 1
            self.protocolos[tipo] += 1
            if self.args.salida:
                self.pkts.append(pkt)
        except Exception, e:
            print "Error obteniendo tipo ({0}: {1})".format(str(e.type), str(e))

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
                res += u"Protocolo {0}: {1}\n".format(key, value)
            res += u"Entropía: {0}".format(self.entropia)
        return res

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
    args = parser.parse_args(argv[1:])
    run = Run(args)
    run.correr()
    print run.resultados()

if __name__ == '__main__':
    try:
        if os.geteuid():
            print u"Tenés que correrlo con sudo"
            sys.exit(1) 
    except OSError:
        pass
    main(sys.argv)

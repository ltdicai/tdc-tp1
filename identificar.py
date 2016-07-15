#! /usr/bin/python
 # -*- coding: utf-8 -*-

import os
import sys
import argparse
import socket
import math
from scapy import utils
from scapy.all import sniff
from collections import defaultdict

WHO_IS = 1
IS_AT = 2

def reverse_dict(dict_, one=False):
    if one:
        res = dict()
    else:
        res = defaultdict(set)
    for key, value in dict_.items():
        if one:
            res[value] = key
        else:
            res[value].add(key)
    return dict(res)

class Identificador(object):
    def __init__(self, args):
        self.args = args
        self.offline = bool(args.pcap)
        self.total_paquetes = 0
        self.entropia = 0
        self.pkts = list()
        self.contador = defaultdict(int)
        self.contador_ip = defaultdict(int)
        self.tabla_arp = defaultdict(set)
        self.mac2ip = None
        self.grafo = defaultdict(int)

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
            arp_pkt = pkt["ARP"]
            mac_src = arp_pkt.hwsrc
            ip_src = arp_pkt.psrc
            if ip_src == "0.0.0.0": # ARP Probe
                return
            self.tabla_arp[mac_src].add(ip_src)
            ip_dst = arp_pkt.pdst
            mac_dst = None
            self.contador_ip[ip_dst] += 1
            if arp_pkt.op == IS_AT:
                mac_dst = arp_pkt.hwdst
                self.grafo["{0}/{1}-{2}/{3}".format(mac_dst, ip_dst, mac_src, ip_src)] += 1
            self.contador[mac_src] += 1
            if mac_dst:
                self.contador[mac_dst] += 1 
            self.total_paquetes += 1
            if self.args.salida:
                self.pkts.append(pkt)
        except Exception, e:
            print "Error procesando paquete({0})".format(type(e))
            raise e

    @staticmethod
    def filtrar(pkt):
        return "ARP" in pkt

    def finalizar(self):
        if self.total_paquetes and self.args.salida:
            utils.wrpcap(self.args.salida + ".pcap", self.pkts)
        for key, value in self.tabla_arp.items():
            print "%s: %s" % (key, str(list(value)))
        entropia = 0
        # total_paquetes = sum(self.contador.values())
        # for key, value in self.contador.items():
        #     prob = float(value)/total_paquetes
        #     print "{0}: {1}".format(key, -math.log(prob, 2))
        #     entropia -= prob * math.log(prob, 2)
        # print "Entropía: ", entropia
        total_paquetes = sum(self.contador_ip.values())
        for key, value in self.contador_ip.items():
            prob = float(value)/total_paquetes
            entropia -= prob * math.log(prob, 2)
            print "{0:15},{1:>},{2:>}".format(key, value, -math.log(prob, 2))
        print "Entropía: ", entropia

    def resultados(self):
        res = u"";
        for key, value in self.contador.items():
            res += u"{0}: {1}\n".format(key, value)
        for key, value in self.grafo.items():
            src, dst = key.split("-")
            mac_src, ip_src = src.split("/")
            mac_dst, ip_dst = dst.split("/")
            res += u"Host {ip_src}({mac_src}) quiere hablar con {ip_dst}({mac_dst}) {veces} veces\n".format(
                ip_src=ip_src,
                ip_dst=ip_dst,
                mac_src=mac_src,
                mac_dst=mac_dst,
                veces=value
            )
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
    parser.add_argument(
        "--tiempo", "-t", type=int, default=None, 
        help=u"Correr hasta tantos segundos"
    )
    args = parser.parse_args(argv[1:])
    ident = Identificador(args)
    ident.correr()
    print ident.resultados().encode("utf-8")

if __name__ == '__main__':
    try:
        if os.geteuid():
            print u"Tenés que correrlo con sudo"
            sys.exit(1) 
    except (OSError, AttributeError):
        pass
    main(sys.argv)



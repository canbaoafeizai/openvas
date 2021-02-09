#!/usr/bin/python
# -*- coding: UTF-8 -*-
from urllib import request
from xml.etree import ElementTree
import xml.etree.cElementTree as ET
class parse(object):
    def __init__(self,xmlstr):
        self.str=xmlstr
    def get_item_text(self,item):
        data = ElementTree.XML(self.str)
        tree = ET.ElementTree(data)
        # root = tree.getroot()
        node = tree.find(item)
        # print(node.text)
        return node.text
    def get_item_attr(self,item):
        data = ElementTree.XML(self.str)
        tree = ET.ElementTree(data)
        # root = tree.getroot()
        node = tree.find(item)
        # print(node.attrib)
        return node.attrib


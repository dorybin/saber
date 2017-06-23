#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
pcap处理界面部分
'''

import wx
import os
import sys

from pcap_recap import insertTunnelHeads #引用模块中的函数 


class MyDialog(wx.Dialog): 
   def __init__(self, parent, title): 
      super(MyDialog, self).__init__(parent, title = title, size = (250,150)) 
      panel = wx.Panel(self) 
      label = wx.StaticText(panel, label = "V1.0", pos = (100,40)) 
      self.btn = wx.Button(panel, wx.ID_OK, label = "ok", size = (50,20), pos = (90,70))

class Mywin(wx.Frame): 
            
   def __init__(self, parent, title): 
      super(Mywin, self).__init__(parent, title = title, size = (800,600))  

      self.InitUI() 
      #self.text = wx.TextCtrl(self,-1,size=wx.DefaultSize,style = wx.TE_MULTILINE) 
      self.Centre() 
      self.Show(True)
      self.Fit()

   def InitUI(self):    
      menubar = wx.MenuBar() 
      '''
      fileMenu = wx.Menu() 
      newitem = wx.MenuItem(fileMenu,wx.ID_NEW,text = "File",kind = wx.ITEM_NORMAL) 
      ##newitem.SetBitmap(wx.Bitmap("new.bmp")) 
      fileMenu.Append(newitem)
      fileMenu.AppendSeparator()
      '''

      '''
      menu set
      '''
      fileMenu = wx.Menu() 
      aboutitem = wx.MenuItem(fileMenu,100,text = "About",kind = wx.ITEM_NORMAL) 
      ##aboutitem.SetBitmap(wx.Bitmap("new.bmp")) 
      fileMenu.Append(aboutitem)
      menubar.Append(fileMenu, '&Help') 

      self.SetMenuBar(menubar) 
      self.Bind(wx.EVT_MENU, self.menuhandler) 

      '''
      text set
      '''
      panel = wx.Panel(self) 
      hbox1 = wx.BoxSizer(wx.HORIZONTAL)  # wx.HORIZONTAL wx.VERTICAL

      self.l1 = wx.StaticText(panel, label = "Input:", pos = (70,84)) 
      hbox1.Add(self.l1) 
      self.dir1 = wx.TextCtrl(panel, style = wx.TE_LEFT, pos = (120,80), size = (460,30)) 
      hbox1.Add(self.dir1) 
      self.butten1 = wx.Button(panel, label = "Open", pos = (600,80)) 
      self.butten1.Bind(wx.EVT_BUTTON, self.OpenFile) 
      hbox1.Add(self.butten1) 

      hbox2 = wx.BoxSizer(wx.HORIZONTAL)
      self.l2 = wx.StaticText(panel, label = "Output:", pos = (70,154)) 
      hbox2.Add(self.l2) 
      self.dir2 = wx.TextCtrl(panel, style = wx.TE_READONLY|wx.TE_LEFT, pos = (120,150), size = (460,30)) 
      hbox2.Add(self.dir2) 
      self.butten2 = wx.Button(panel, label = "Generate", pos = (600,150)) 
      self.butten2.Bind(wx.EVT_BUTTON, self.GenerateOutFile) 
      hbox2.Add(self.butten2) 


   def GenerateOutFile(self, event): 
      #self.InputFile = self.dir1.GetValue()
      self.OutputFile = self.InputDir+'\pkts_out.pcap'
      #self.dir2.Clear()
      self.dir2.SetValue(self.OutputFile)
      insertTunnelHeads(self.InputFile, self.OutputFile)

   def menuhandler(self, event): 
      id = event.GetId() 
      #if id == wx.ID_NEW: 
      #   self.OpenFile(event)
      if id == 100: 
         #self.Onmsgbox(event)
         self.OnModeless(event)

   def OpenFile(self, event): 
      wildcard = "Pcap Files (*.pcap)|*.pcap" 
      dlg = wx.FileDialog(self, "Choose a file", os.getcwd(), "", wildcard, 0) 

      if dlg.ShowModal() == wx.ID_OK:
         self.dir1.SetValue(dlg.GetPath())
         self.InputFile = dlg.GetPath()
         self.InputDir = dlg.GetDirectory()

      dlg.Destroy() 

   def OnModeless(self, event): 
      a = MyDialog(self, "Icap").Show()
   def Onmsgbox(self, event): 
      wx.MessageBox("V1.0", "Icap" ,wx.OK | wx.ICON_INFORMATION)  


ex = wx.App() 
Mywin(None,'Icap') 

if __name__ == '__main__': 	
    ex.MainLoop() 
#!/usr/bin/python2
# -*- coding: utf-8 -*-
import dpkt
import datetime
import socket
import win_inet_pton
import os
from stat import S_ISDIR
import paramiko
#import pyshark
import sqlite3 as lite
import sys
#from scapy.all import *
import time
import datetime
#import pymysql.cursors
import MySQLdb
from numpy import array
from os import walk
from datetime import date, timedelta
local_directory_Win_Snort_Com = "C:\\Pcap2XML\\Win12_Snort_Com"
local_directory_Win_Snort_Reg = "C:\\Pcap2XML\\Win12_Snort_Reg"
local_directory_Win_Suricata_ET = "C:\\Pcap2XML\\Win12_Suricata_ET"
local_directory_Ubuntu_Snort_Com = "C:\\Pcap2XML\\Ubuntu_Snort_Com"
local_directory_Ubuntu_Snort_Reg = "C:\\Pcap2XML\\Ubuntu_Snort_Reg"
local_directory_Ubuntu_Suricata_ET = "C:\\Pcap2XML\\Ubuntu_Suricata_ET"
local_directory_Ubuntu_Bro = "C:\\Pcap2XML\\Ubuntu_Bro"
local_directory_FreeBSD_Snort_Com = "C:\\Pcap2XML\\FreeBSD_Snort_Com"
local_directory_FreeBSD_Snort_Reg = "C:\\Pcap2XML\\FreeBSD_Snort_Reg"
local_directory_FreeBSD_Suricata_ET = "C:\\Pcap2XML\\FreeBSD_Suricata_ET"
local_directory_CentOS_Snort_Com = "C:\\Pcap2XML\\CentOS_Snort_Com"
local_directory_CentOS_Snort_Reg = "C:\\Pcap2XML\\CentOS_Snort_Reg"
local_directory_CentOS_Suricata_ET = "C:\\Pcap2XML\\CentOS_Suricata_ET"
local_directory_Input_data = "C:\\Pcap2XML\\Input_pcap_data"
remote_directory_windows = "C:\\Pcap"
remote_directory_ubuntu="/home/ubuntu/Data/"
remote_directory_FreeBSD="/home/FreeBSD1/Data/"
remote_directory_FreeBSD_="/home/FreeBSD2/Data/"
remote_directory_CentOS="/tmp/Data/"



def copy_pcap_files_via_ssh(IP_address,user_name,pass_word,remote_path, local_path):
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(IP_address,username=user_name,password=pass_word)
  #  local_full_path =''.join([local_directory ,local_file_name])
  #  if remote_directory!=remote_directory_windows:
  #      cmd1='cp '
  #      cmd2='/*.pcap '
  #      cmd=''.join([cmd1 ,remote_directory,cmd2,remote_directory,remote_file_to_copy])
  #      stdin, stdout, stderr = ssh.exec_command(cmd)
  #  else:
  #      cmd1='copy '
  #      cmd2='\\*.pcap '
  #      cmd3='\\'
  #      cmd=''.join([cmd1 ,remote_directory,cmd2,remote_directory,cmd3,remote_file_to_copy])
  #      stdin, stdout, stderr = ssh.exec_command(cmd)
        
    #cmd="ls"
    #stdin, stdout, stderr = client.exec_command('ls -l')
    ftp=ssh.open_sftp()
  #  ftp.chdir(remote_directory)
  #  ftp.get(remote_file_to_copy,local_full_path)

    path=remote_path
    files=[]
    folders=[]
    for f in ftp.listdir_attr(remote_path):
        if S_ISDIR(f.st_mode):
            folders.append(f.filename)
        else:
            files.append(f.filename)
    print (files)

    ftp.chdir(remote_path)
    Local_folder=local_path
    for file in files:
            ftp.get(file,os.path.join(Local_folder,file))

#for line in stdout:
#    print line.strip('\n')
    ssh.close()

           


def mysql_database_query(d_name,User_name,Password):

    conn=MySQLdb.connect(host="192.168.1.2",db=d_name, user=User_name, passwd=Password)
    cursor_mysql= conn.cursor()
    str1='USE '
    USE_DB=''.join([str1,d_name])
    cursor_mysql.execute(USE_DB)
    todaysdate = time.strftime("%Y-%m-%d")
    yesterday = date.today() - timedelta(1)
    yesterday=yesterday.strftime('%Y-%m-%d')
    #cursor_mysql.execute("select  ip_id,inet_ntoa(ip_src),inet_ntoa(ip_dst),ip_proto from iphdr,event where iphdr.sid=event.sid and iphdr.cid=event.cid and date(event.timestamp)='2016-07-25'")
    #data1 = cursor_mysql.fetchall()
    #cursor_mysql.execute("select  tcp_sport,tcp_dport from tcphdr,event where tcphdr.cid=event.cid and date(event.timestamp)='2016-07-25'")
    #data2 = cursor_mysql.fetchall()
    #cursor_mysql.execute("select  udp_sport,udp_dport from udphdr,event where udphdr.cid=event.cid and date(event.timestamp)='2016-07-25'")


    #cursor_mysql.execute("select  inet_ntoa(ip_src),inet_ntoa(ip_dst),ip_id,ip_proto from iphdr,event where iphdr.sid=event.sid and iphdr.cid=event.cid and date(event.timestamp)='2016-07-25'")
    #data1 = cursor_mysql.fetchall()


    cursor_mysql.execute("select  inet_ntoa(ip_src),inet_ntoa(ip_dst),ip_id,tcp_sport,tcp_dport,sig_sid,time(timestamp),date(timestamp) from iphdr,tcphdr,signature,event \
                          where signature.sig_id=event.signature and iphdr.sid=event.sid and iphdr.cid=event.cid and tcphdr.cid=event.cid and tcphdr.sid=event.sid and date(event.timestamp)>= %s\
                          and date(event.timestamp)<= %s",(yesterday,todaysdate))
    data1 = cursor_mysql.fetchall()
    cursor_mysql.execute("select  inet_ntoa(ip_src),inet_ntoa(ip_dst),ip_id,udp_sport,udp_dport,sig_sid,time(timestamp),date(timestamp) from iphdr,udphdr,event,signature \
                          where iphdr.sid=event.sid and iphdr.cid=event.cid and udphdr.cid=event.cid and udphdr.sid=event.sid and signature.sig_id=event.signature and date(event.timestamp)>= %s\
                          and date(event.timestamp)<= %s",(yesterday,todaysdate))
    data2 = cursor_mysql.fetchall()

    cursor_mysql.execute("select  inet_ntoa(ip_src),inet_ntoa(ip_dst),ip_id,sig_sid,time(timestamp),date(timestamp) from icmphdr,iphdr,signature,event where icmphdr.sid=event.sid and icmphdr.cid=event.cid \
                          and iphdr.sid=event.sid and iphdr.cid=event.cid and signature.sig_id=event.signature and date(event.timestamp)>= %s and date(event.timestamp)<= %s",(yesterday,todaysdate))
    data3 = cursor_mysql.fetchall()
    
    return data1,data2,data3

def creat_tables_sqlite():
    
    
        con=lite.connect("C:\\Pcap2XML\\Pcap_to_Sqlite.db")
        cur=con.cursor()
        con.text_factory = str
        #table_name = 'my_table_2'   # name of the table to be created
        #id_column = 'my_1st_column' # name of the PRIMARY KEY column
        #new_column1 = 'my_2nd_column'  # name of the new column
        #new_column2 = 'my_3nd_column'  # name of the new column
        #column_type = 'TEXT' # E.g., INTEGER, TEXT, NULL, REAL, BLOB
        #default_val = 'Hello World' # a default value for the new column rows

        #cur.execute('SELECT SQLITE_VERSION()')
        #data=cur.fetchone()
        #print("SQLITE Version: %s" % data)
         

        #cur.execute("CREATE TABLE Win_Snort_Com(SID TEXT,Date TEXT,Time TEXT,ip_ID INT,Source_IP TEXT,Destination_IP TEXT,Source_Port INT ,Destination_Port INT,Detection TEXT)")
        #cur.execute("CREATE TABLE Win_Snort_Reg(Date TEXT,Time TEXT,ip_ID INT,Source_IP TEXT,Destination_IP TEXT,Detection TEXT)")
        #cur.execute("CREATE TABLE Win_Suricata_ET(ip_ID INT,Source_IP TEXT,Destination_IP TEXT,Detection TEXT)")
        #cur.execute("CREATE TABLE Ubuntu_Snort_Reg(ip_ID INT,Source_IP TEXT,Destination_IP TEXT,Detection TEXT)")

        #cur.execute("CREATE TABLE Packet_data(SID TEXT,PID TEXT,Date TEXT,Time TEXT,ip_ID INT,Source_IP TEXT,Destination_IP TEXT,Protocol TEXT,Source_Port INT,Destination_Port INT,Detection TEXT)")

        cur.execute("CREATE TABLE IF NOT EXISTS Input(Input_ID INTEGER PRIMARY KEY AUTOINCREMENT,ip_ID INT,Source_IP TEXT,Destination_IP TEXT,Protocol TEXT,Source_Port INT,Destination_Port INT)")
        cur.execute("CREATE TABLE IF NOT EXISTS Results(Defense_ID INTEGER,Input_ID INTEGER,Detection_ID INTEGER,Signature_ID INTEGER,TimeStamp INTEGER,FOREIGN KEY(Defense_ID) REFERENCES Defense_Tools(Defense_ID),\
                    FOREIGN KEY(Input_ID) REFERENCES Input(Input_ID),FOREIGN KEY(Detection_ID) REFERENCES Detection(Detection_ID))")
        cur.execute("CREATE TABLE IF NOT EXISTS Defense_Tools(Defense_ID INTEGER PRIMARY KEY AUTOINCREMENT,OS_ID TEXT,Name_of_OS TEXT,Types_of_Defense TEXT,Version_of_Rule_Set TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS Detection(Detection_ID INTEGER PRIMARY KEY AUTOINCREMENT,Detection TEXT)")
       
        con.commit()
        
        #con.execute('''DELETE FROM Win_Snort_Com''')   #Deleting the record
        #con.execute('''DELETE FROM Packet_data''')   #Deleting the record
        # con.execute ('''DELETE FROM Defense_Tools WHERE Defense_ID = (SELECT MAX(Defense_ID) FROM Defense_Tools)''')
        #con.execute('''DROP TABLE Win_Snort_Com''')   #Deleting the table
        #con.execute("ALTER TABLE {tn} ADD COLUMN '{cn}' {ct}"\
        #        .format(tn='Win_Snort_Com', cn='Detection', ct='TEXT'))
        #cur.execute("INSERT INTO Win_Snort_Com (ip_ID,Source_IP,Destination_IP) VALUES(1,'192.168.1.2','192.168.1.3')")
        return con
    
def populate_Defense_tools(Name_of_OS,con):
       
    
    table_name='Defense_Tools'
    cur=con.cursor()
    
    if Name_of_OS =='Win_Snort_Com':
    #    DefenseID='1'
        OSID='1'    #previously OSID="'1'"
        NameofOS='Win12_Snort_Com'
        Typesof_Defense='IDS'
        VersionofRule_Set='Community'
        
    if Name_of_OS =='Win_Snort_Reg':
    #    DefenseID='2'
        OSID='1'
        NameofOS='Win12_Snort_Reg'
        Typesof_Defense='IDS'
        VersionofRule_Set='Reg'   
        
    if Name_of_OS =='Win_Suricata_ET':
     #   DefenseID='3'
        OSID='1'
        NameofOS='Win12_Suricata_ET'
        Typesof_Defense='IDS'
        VersionofRule_Set='ET'
    if Name_of_OS == 'Ubuntu_Snort_Com':
         
     #   DefenseID='3'
        OSID='2'
        NameofOS='Ubuntu_Snort_Com'
        Typesof_Defense='IDS'
        VersionofRule_Set='Community'

    if Name_of_OS == 'Ubuntu_Snort_Reg':
        
     #   DefenseID='3'
        OSID='2'
        NameofOS='Ubuntu_Snort_Reg'
        Typesof_Defense='IDS'
        VersionofRule_Set='Registered'

    if Name_of_OS == 'Ubuntu_Suricata_ET':
     #   DefenseID='3'
        OSID='2'
        NameofOS='Ubuntu_Suricata_ET'
        Typesof_Defense='IDS'
        VersionofRule_Set='ET'
    if Name_of_OS == 'Ubuntu_Bro':
     #   DefenseID='3'
        OSID='2'
        NameofOS='Ubuntu_Bro'
        Typesof_Defense='IDS'
        VersionofRule_Set='Bro Scripts'
    if Name_of_OS == 'FreeBSD_Snort_Com':
     #   DefenseID='3'
        OSID='3'
        NameofOS='FreeBSD_Snort_Com'
        Typesof_Defense='IDS'
        VersionofRule_Set='Community' 
    if Name_of_OS == 'FreeBSD_Snort_Reg':
     #   DefenseID='3'
        OSID='3'
        NameofOS='FreeBSD_Snort_Reg'
        Typesof_Defense='IDS'
        VersionofRule_Set='Reg'
    if Name_of_OS == 'FreeBSD_Suricata_ET':
     #   DefenseID='3'
        OSID='3'
        NameofOS='FreeBSD_Suricata_ET'
        Typesof_Defense='IDS'
        VersionofRule_Set='ET'
    if Name_of_OS == 'Centos_Snort_Com':
     #   DefenseID='3'
        OSID='4'
        NameofOS='Centos_Snort_Com'
        Typesof_Defense='IDS'
        VersionofRule_Set='Community'
    if Name_of_OS == 'Centos_Snort_Reg':
     #   DefenseID='3'
        OSID='4'
        NameofOS='Centos_Snort_Reg'
        Typesof_Defense='IDS'
        VersionofRule_Set='Reg'
    if Name_of_OS == 'Centos_Suricata_ET':
     #   DefenseID='3'
        OSID='4'
        NameofOS='Centos_Suricata_ET'
        Typesof_Defense='IDS'
        VersionofRule_Set='ET'
    if Name_of_OS == 'Input':
     #   DefenseID='3'
        OSID='2'
        NameofOS='Ubuntu_8_Input_generation'
        Typesof_Defense='Input Generation/Pcap Saving'
        VersionofRule_Set='N/A'
    
    
  #  sql= 'INSERT INTO ' + table_name + ' (OS_ID,Name_of_OS,Types_of_Defense,Version_of_Rule_Set) ' + 'VALUES(?,?,?,?),'+ '('+'%s' % OSID +','+'%s' % NameofOS + ',' + '%s' % Typesof_Defense + ',' + '%s' % VersionofRule_Set+')'
  #  cur.execute(sql)
    cur.execute("""INSERT INTO Defense_Tools (OS_ID,Name_of_OS,Types_of_Defense,Version_of_Rule_Set) VALUES(?,?,?,?)""",(OSID,NameofOS ,Typesof_Defense ,VersionofRule_Set))
    last_id_in_Defense_Tools = cur.lastrowid

    con.commit()
    
    return last_id_in_Defense_Tools


    
    
def Collecting_Pcapfiles():
    
     #########Input Data ################
    
    copy_pcap_files_via_ssh('192.168.1.16','root','D3Sepsrccity',remote_directory_ubuntu,local_directory_Input_data)
   

    #########Windows-12 Snort with Community Rules ################

  #  file_to_copy="Data_Win_Snort_Com.pcap"
  #  local_file="Data_Win_Snort_Com_3.pcap"
  #  copy_pcap_files_via_ssh('192.168.1.11','Administrator','Dynamic2sun',remote_directory_windows,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.11','Administrator','Dynamic2sun',remote_directory_windows,local_directory_Win_Snort_Com)
    ######## Windows-12 Snort with Registered Rules ##############

 #   file_to_copy="Data_Win_Snort_Reg.pcap"
 #   local_file="Data_Win_Snort_Reg.pcap"
 #   copy_pcap_files_via_ssh('192.168.1.13','Administrator','Dynamic2sun',remote_directory_windows,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.13','Administrator','Dynamic2sun',remote_directory_windows,local_directory_Win_Snort_Reg)
  #  copy_pcap_files_via_ssh('138.40.246.69','Administrator','Dynamic2sun',remote_directory_windows,Windows_file_to_copy,local_file)

    ######## Windows-12 Suricata with Emerging Threats Rules ##############

  #  file_to_copy="Data_Win_Suricata_ET.pcap"    
  #  local_file="Data_Win_Suricata_ET.pcap"
    copy_pcap_files_via_ssh('192.168.1.12','Administrator','Dynamic2sun',remote_directory_windows,local_directory_Win_Suricata_ET)
  #  copy_pcap_files_via_ssh('138.40.246.71','Administrator','Dynamic2sun',remote_directory_windows,Windows_file_to_copy,local_file)

    ######## Ubuntu Snort with community Rules ##############

#    file_to_copy="Data_Ubuntu_Snort_Com.pcap"
#    local_file="Data_Ubuntu_Snort_Com.pcap"
#    copy_pcap_files_via_ssh('192.168.1.1','root','D3Sepsrccity',remote_directory_ubuntu,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.1','root','D3Sepsrccity',remote_directory_ubuntu,local_directory_Ubuntu_Snort_Com)
  #  copy_pcap_files_via_ssh('138.40.246.21','root','D3Sepsrccity',remote_directory_ubuntu,Ubuntu_file_to_copy,local_file)
       
    ######## Ubuntu Snort with Registered Rules ##############

 #   file_to_copy="Data_Ubuntu_Snort_reg.pcap"
 #   local_file="Data_Ubunt_Snort_reg.pcap"
 #   copy_pcap_files_via_ssh('192.168.1.3','root','D3Sepsrccity',remote_directory_ubuntu,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.3','root','D3Sepsrccity',remote_directory_ubuntu,local_directory_Ubuntu_Snort_Reg)
  #  copy_pcap_files_via_ssh('138.40.246.24','root','D3Sepsrccity',remote_directory_ubuntu,Ubuntu_file_to_copy,local_file)

    ######## Ubuntu Suricata with ET Rules ##############

  #  Ubuntu_file_to_copy="Data_Ubuntu_suricata_ET.pcap"
  #  local_file="Data_Ubuntu_suricata_ET.pcap"
  #  copy_pcap_files_via_ssh('192.168.1.4','root','D3Sepsrccity',remote_directory_ubuntu,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.4','root','D3Sepsrccity',remote_directory_ubuntu,local_directory_Ubuntu_Suricata_ET)
  #  copy_pcap_files_via_ssh('138.40.246.22','root','D3Sepsrccity',remote_directory_ubuntu,Ubuntu_file_to_copy,local_file)

    ######## Ubuntu Bro ##############

  #  file_to_copy="Data_Ubuntu_Bro.pcap"
  #  local_file="Data_Ubuntu_Bro.pcap"
   # copy_pcap_files_via_ssh('192.168.1.4','root','D3Sepsrccity',remote_directory_ubuntu,Ubuntu_file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.21','root','D3Sepsrccity',remote_directory_ubuntu,local_directory_Ubuntu_Bro)
     
 #   copy_pcap_files_via_ssh('138.40.246.23','root','D3Sepsrccity',remote_directory_ubuntu,file_to_copy,local_file)

    ####### FreeBSD Snort with Community Rules ########
        
 #   file_to_copy="Data_FreeBSD_Snort_Com.pcap"
 #   local_file="Data_FreeBSD_Snort_Com.pcap"        
 #   copy_pcap_files_via_ssh('192.168.1.7','root','D3Sepsrccity',remote_directory_FreeBSD,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.7','root','D3Sepsrccity',remote_directory_FreeBSD,local_directory_FreeBSD_Snort_Com)
    
 #   copy_pcap_files_via_ssh('138.40.246.51','root','D3Sepsrccity',remote_directory_FreeBSD,file_to_copy,local_file)

    ####### FreeBSD Snort with Registered Rules ########
        
         
    copy_pcap_files_via_ssh('192.168.1.8','root','D3Sepsrccity',remote_directory_FreeBSD,local_directory_FreeBSD_Snort_Reg)
    
 #   copy_pcap_files_via_ssh('138.40.246.51','root','D3Sepsrccity',remote_directory_FreeBSD,file_to_copy,local_file)
 
    ####### FreeBSD Suricatat with ET Rules ########
        
         
    copy_pcap_files_via_ssh('192.168.1.30','root','D3Sepsrccity',remote_directory_FreeBSD_,local_directory_FreeBSD_Suricata_ET)
    
 #   copy_pcap_files_via_ssh('138.40.246.51','root','D3Sepsrccity',remote_directory_FreeBSD,file_to_copy,local_file)
 
    ####### CentOS Snort with Community Rules ########
        
 #   file_to_copy="Data_CentOS_Snort_Com.pcap"
 #   local_file="Data_CentOS_Snort_Com.pcap"
 #   copy_pcap_files_via_ssh('192.168.1.5','root','D3Sepsrccity',remote_directory_CentOS,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.5','root','D3Sepsrccity',remote_directory_CentOS,local_directory_CentOS_Snort_Com)   
    
 #   copy_pcap_files_via_ssh('138.40.246.2','root','D3Sepsrccity',remote_directory_CentOS,file_to_copy,local_file)

    ####### CentOS Snort with Registered Rules ########
        
 #   file_to_copy="Data_CentOS_Snort_Com.pcap"
 #   local_file="Data_CentOS_Snort_Com.pcap"
 #   copy_pcap_files_via_ssh('192.168.1.5','root','D3Sepsrccity',remote_directory_CentOS,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.6','root','D3Sepsrccity',remote_directory_CentOS,local_directory_CentOS_Snort_Reg)   
    
 #   copy_pcap_files_via_ssh('138.40.246.2','root','D3Sepsrccity',remote_directory_CentOS,file_to_copy,local_file)

    ####### CentOS Suricata with ET Rules ########
        
 #   file_to_copy="Data_CentOS_Snort_Com.pcap"
 #   local_file="Data_CentOS_Snort_Com.pcap"
 #   copy_pcap_files_via_ssh('192.168.1.10','root','D3Sepsrccity',remote_directory_CentOS,file_to_copy,local_file)
    copy_pcap_files_via_ssh('192.168.1.10','root','D3Sepsrccity',remote_directory_CentOS,local_directory_CentOS_Suricata_ET)   
    
 #   copy_pcap_files_via_ssh('138.40.246.2','root','D3Sepsrccity',remote_directory_CentOS,file_to_copy,local_file)

 

def reading_pcap_files(local_dir):
    cap={}
    i=0
    F={}
    todaysdate = time.strftime("%Y-%m-%d")
    yesterday = date.today() - timedelta(1)
    for (dirpath, dirnames, filenames) in walk(local_dir):
        for f in filenames:
            
            """Open up a test pcap file and print out the packets"""
            t=os.path.getmtime(os.path.join(local_dir,f))
            
            if (datetime.date.fromtimestamp(float(t)).strftime('%Y-%m-%d') ==  todaysdate):

                
                F[i]=open(os.path.join(local_dir,f), 'rb')
                
                cap[i] = dpkt.pcap.Reader(F[i])
                 # cap[i]=pyshark.FileCapture(os.path.join(local_dir,f))
                i+=1
               
            
              
            
    return cap,F

def populating_tables(Pcap_data,F_handle,mysql_data1,mysql_data2,mysql_data3,Defense_ID,Detection_ID1,Detection_ID2,con):
    flag_tcp=0
    flag_udp=0
    flag_icmp=0
    packet_already_Saved=0
    list_of_packet_headers=[]
    list_of_ip_packet_headers=[]
    list_of_tcp_packet_headers=[]
    list_of_udp_packet_headers=[]
    list_of_icmp_packet_headers=[]
    con.text_factory = str
    cur=con.cursor() 
    Input_table_Primarykey_ID=0
    mysql1_list=[tuple((l[0],l[1],l[2],l[3],l[4],str(l[6]),str(l[7]))) for l in mysql_data1]
    mysql2_list=[tuple((l[0],l[1],l[2],l[3],l[4],str(l[6]),str(l[7]))) for l in mysql_data2]
    mysql3_list=[tuple((l[0],l[1],l[2],str(l[4]),str(l[5]))) for l in mysql_data3]
    list_of_ip_packet_headers,list_of_tcp_packet_headers,list_of_udp_packet_headers,list_of_icmp_packet_headers=collect_IP_headers(Pcap_data,F_handle)
    
    s1 = set(mysql1_list)
    s2 = set(mysql2_list)
    s3 = set(mysql3_list)
   

    for (a,b,c,d,e,f,g,h) in list_of_tcp_packet_headers:
        if (a,b,c,d,e,f,g) in s1:
            for j in mysql_data1:
                if (j[0]==a) and (j[1]==b) and (j[2]==c):
                    
                  #  print "TCP"
                                   
                    if packet_already_Saved==0:
                        cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'TCP',d,e))
                        Input_table_Primarykey_ID=cur.lastrowid
                        packet_already_Saved=1
                                
                    cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,Detection_ID1,j[5],h))
                    list(mysql_data1).remove(j)
            
            packet_already_Saved=0
        else:
            cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'TCP',d,e))
            Input_table_Primarykey_ID=cur.lastrowid                    
            cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,Detection_ID2,'-',h))


    for (a,b,c,d,e,f,g,h) in list_of_udp_packet_headers:
        
        if (a,b,c,d,e,f,g) in s2:
            for j in mysql_data2:
                if (j[0]==a) and (j[1]==b) and (j[2]==c):
                    
                  #  print "UDP"
                                   
                    if packet_already_Saved==0:

                        cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'UDP',d,e))
                        Input_table_Primarykey_ID=cur.lastrowid
                        packet_already_Saved=1
                                
                    cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,Detection_ID1,j[5],h))
                    list(mysql_data2).remove(j)

            packet_already_Saved=0
            
        else:
            cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'UDP',d,e))
            Input_table_Primarykey_ID=cur.lastrowid                    
            cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,Detection_ID2,'-',h))

    for (a,b,c,d,e,f) in list_of_icmp_packet_headers:
        
        if (a,b,c,d,e) in s3:
            for j in mysql_data3:
                if (j[0]==a) and (j[1]==b) and (j[2]==c):
                    
                  #  print "ICMP"
                          
                    if packet_already_Saved==0:
                        cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'ICMP','-','-'))
                        Input_table_Primarykey_ID=cur.lastrowid
                        packet_already_Saved=1
                                 
                    cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,Detection_ID1,j[3],f))
                    list(mysql_data3).remove(j)

            packet_already_Saved=0
            
        else:
            cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'ICMP','-','-'))
            Input_table_Primarykey_ID=cur.lastrowid
            cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,Detection_ID2,'-',f))
                 
            
           
        
 
    con.commit()
    return list_of_ip_packet_headers
        
def collect_IP_headers(Caps,F_handle):
    todaysdate = time.strftime("%Y-%m-%d")
    tomorrow=datetime.date.today() + datetime.timedelta(days=1)
    yesterday=datetime.datetime.now() - datetime.timedelta(days=1)
    tomorrow_date=tomorrow.strftime("%Y-%m-%d")
    yesterday_date=yesterday.strftime("%Y-%m-%d")
    list_of_tcp_packet_headers=[]
    list_of_udp_packet_headers=[]
    list_of_icmp_packet_headers=[]
    list_of_ip_packet_headers=[]
    for i in range(len(Caps)):            
        input=Caps[i]
        for timestamp, buf in input:
            if (datetime.date.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d') == yesterday_date):
                
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip=eth.data
                    list_of_ip_packet_headers.append(tuple([socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),ip.id,timestamp]))
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp=ip.data
                        list_of_tcp_packet_headers.append(tuple([socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),ip.id,\
                                                                 tcp.sport,tcp.dport,datetime.datetime.fromtimestamp(float(timestamp)).strftime('%H:%M:%S'),\
                                                                 datetime.date.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d'),timestamp]))
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp=ip.data
                        list_of_udp_packet_headers.append(tuple([socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),ip.id,udp.sport,udp.dport,\
                                                                 datetime.datetime.fromtimestamp(float(timestamp)).strftime('%H:%M:%S'),\
                                                                 datetime.date.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d'),timestamp]))
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        icmp=ip.data
                        list_of_icmp_packet_headers.append(tuple([socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),ip.id,\
                                                                  datetime.datetime.fromtimestamp(float(timestamp)).strftime('%H:%M:%S'),\
                                                                  datetime.date.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d'),timestamp]))                        
                        
                        
          
        F_handle[i].close()
    
    return list_of_ip_packet_headers,list_of_tcp_packet_headers,list_of_udp_packet_headers, list_of_icmp_packet_headers

def packet_tracing_from_input_to_output(Caps,F_handle,Defense_tool_ip_header,Defense_ID,con):
    packet_traced=0
    Input_table_Primarykey_ID=0
    con.text_factory = str
    cur=con.cursor()
    list_of_ip_packet_headers=[]
    list_of_tcp_packet_headers=[]
    list_of_udp_packet_headers=[]
    list_of_icmp_packet_headers=[]
    list_of_ip_packet_headers,list_of_tcp_packet_headers,list_of_udp_packet_headers, list_of_icmp_packet_headers=collect_IP_headers(Caps,F_handle)
    print len(Defense_tool_ip_header)
    print len(list_of_ip_packet_headers)
    Defense_tool_ip_header_no_timestamp=[tuple((l[0],l[1],l[2])) for l in Defense_tool_ip_header]
    s = set(Defense_tool_ip_header_no_timestamp)
    Packet_not_traced = [(a,b,c,d) for (a,b,c,d) in list_of_ip_packet_headers if (a,b,c) not in s]
   # for IP_headers in list_of_packet_headers:
   #     for Ip_header in Defense_tool_ip_header:
   #         if (float(Ip_header[3]) > (float(IP_headers[3])-10.0)) and (float(Ip_header[3]) < (float(IP_headers[3])+10.0)):                                         
   #             if (socket.inet_ntoa(IP_headers[0])==socket.inet_ntoa(Ip_header[0])) and (socket.inet_ntoa(IP_headers[1])==socket.inet_ntoa(Ip_header[1])) and  (IP_headers[2]==Ip_header[2]):
   #                 packet_traced=1
   #                 print("Packet Traced")
   #                 Defense_tool_ip_header.remove(Ip_header)
   #                 break
   #             if (float(Ip_header[3]) > (float(IP_headers[3])+10.0)):
   #                 break
   #     if packet_traced==1:
   #         packet_traced=0
                    
   #     else:
   #         print("Packet not Traced")
              #  cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(ip.id,socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),'-','-','-'))
              #  Input_table_Primarykey_ID=cur.lastrowid
              #  cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,2,'-',timestamp))
               
        
    #con.commit()
    for (a,b,c,d) in Packet_not_traced:
        cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'-','-','-'))
        Input_table_Primarykey_ID=cur.lastrowid
        cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,2,'-',d))
             
        
    con.commit()
    return Packet_not_traced,list_of_ip_packet_headers
def packet_tracing_from_output_to_input(Input_ip_headers,Defense_tool_ip_header,Defense_ID,con):
    packet_traced=0
    Input_table_Primarykey_ID=0
    con.text_factory = str
    cur=con.cursor()
    
    Defense_tool_ip_header=[tuple(l) for l in Defense_tool_ip_header]
    Defense_tool_ip_header=set(Defense_tool_ip_header)
    input_ip_header_no_timestamp=[tuple((l[0],l[1],l[2])) for l in Input_ip_headers]
    s= set(input_ip_header_no_timestamp)
    
    Packet_not_traced = [(a,b,c,d) for (a,b,c,d) in Defense_tool_ip_header if (a,b,c) not in s]
   # for IP_headers in list_of_packet_headers:
   #     for Ip_header in Defense_tool_ip_header:
   #         if (float(Ip_header[3]) > (float(IP_headers[3])-10.0)) and (float(Ip_header[3]) < (float(IP_headers[3])+10.0)):                                         
   #             if (socket.inet_ntoa(IP_headers[0])==socket.inet_ntoa(Ip_header[0])) and (socket.inet_ntoa(IP_headers[1])==socket.inet_ntoa(Ip_header[1])) and  (IP_headers[2]==Ip_header[2]):
   #                 packet_traced=1
   #                 print("Packet Traced")
   #                 Defense_tool_ip_header.remove(Ip_header)
   #                 break
   #             if (float(Ip_header[3]) > (float(IP_headers[3])+10.0)):
   #                 break
   #     if packet_traced==1:
   #         packet_traced=0
                    
   #     else:
   #         print("Packet not Traced")
              #  cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(ip.id,socket.inet_ntoa(ip.src),socket.inet_ntoa(ip.dst),'-','-','-'))
              #  Input_table_Primarykey_ID=cur.lastrowid
              #  cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,2,'-',timestamp))
               
        
    #con.commit()
    for (a,b,c,d) in Packet_not_traced:
        cur.execute("""INSERT INTO Input (ip_ID,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port) VALUES(?,?,?,?,?,?)""",(c,a,b,'-','-','-'))
        Input_table_Primarykey_ID=cur.lastrowid
        cur.execute("""INSERT INTO Results VALUES(?,?,?,?,?)""",(Defense_ID,Input_table_Primarykey_ID,3,'-',d))
              
        
    con.commit()
    return Packet_not_traced                    


#os.system("C:\\Pcap2XML\\Pcap2XML.exe C:\\Pcap2XML\\Data_Win_Snort_Com.pcap -x C:\\Pcap2XML\\Data_Win_Snort_Com.xml -s C:\\Pcap2XML\\Data_Win_Snort_Com.db --offset=0")

if __name__ == "__main__":

    time_start=time.clock()
    Defense_tools_ID=0
    Detection_ID1=0
    Detection_ID2=0
    Detection_ID3=0
    Detection_ID4=0
    cap={}
    temp=[]
    Input_packet_headers=[]
    List_of_Packet_headers=[]
    Combined_list_of_Packets=[]
#####Collecting Pcap Files ###########
    Collecting_Pcapfiles()
    con=creat_tables_sqlite()
    con.text_factory = str
    cur=con.cursor()
 
 #   con.execute('''DELETE FROM sqlite_sequence where name=Defense_Tools''')
 #   con.execute('''DELETE FROM Detection''')
 #   cur.execute("""INSERT INTO Defense_Tools (Defense_ID) VALUES(?)""",1)
 #   con.commit()
 #   cur.execute("""INSERT INTO Detection VALUES(?,?)""",(1,'YES'))
 #   Detection_ID1 = cur.lastrowid
 #   cur.execute("""INSERT INTO Detection VALUES(?,?)""",(0,'NO'))
 #   Detection_ID2  = cur.lastrowid
 #   cur.execute("""INSERT INTO Detection VALUES(?,?)""",(2,'Packet not traced from input_to_output'))
 #   Detection_ID3  = cur.lastrowid
 #   cur.execute("""INSERT INTO Detection VALUES(?,?)""",(3,'Packet not traced from output_to_input'))
 #   Detection_ID4  = cur.lastrowid
 #   con.commit()
    Detection_ID1=1
    Detection_ID2=0
    Detection_ID3=2
    Detection_ID4=3
  #  Defense_tools_ID=populate_Defense_tools('Win_Snort_Com',con)
    print "Processing WinSnortCom Data............"
    Defense_tools_ID=1
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("WinSnortCom",'WinSnortCom',"D3Sepsrccity")
   #cap1=pyshark.FileCapture("C:\\Pcap2XML\\Data_Win_Snort_Com_2.pcap")
    cap,File_handler=reading_pcap_files(local_directory_Win_Snort_Com)
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handler=reading_pcap_files(local_directory_Input_data)
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)

    print "Processing Win_Snort_Reg Data............"
    #Defense_tools_ID=populate_Defense_tools('Win_Snort_Reg',con)
    Defense_tools_ID=2
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("Win_Snort_Reg",'W_Snort_Reg',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_Win_Snort_Reg) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1, mysql_Data2, mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handler=reading_pcap_files(local_directory_Input_data)
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)


    print "Processing WinSuricataET Data............"
   #Defense_tools_ID=populate_Defense_tools('Win_Suricata_ET',con)
    Defense_tools_ID=3
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("WinSuricataET",'WinSuricataET',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_Win_Suricata_ET) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handler=reading_pcap_files(local_directory_Input_data)
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)
    

    print "Processing Ubuntu_Snort_Com Data............"
    #Defense_tools_ID=populate_Defense_tools('Ubuntu_Snort_Com',con)
    Defense_tools_ID=4
    mysql_Data1,mysql_Data2,mysql_Data3=mysql_database_query("Ubuntu_Snort_Com",'U_Snort_Com',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_Ubuntu_Snort_Com) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handler=reading_pcap_files(local_directory_Input_data)
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)
   

    print "Processing Ubuntu_Snort_Reg Data............"
    #Defense_tools_ID=populate_Defense_tools('Ubuntu_Snort_Reg',con)
    Defense_tools_ID=5
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("Ubuntu_Snort_Reg",'U_Snort_Reg',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_Ubuntu_Snort_Reg)
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handler=reading_pcap_files(local_directory_Input_data)
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)

    print "Processing Ubuntu_Suricata_ET Data............"
    #Defense_tools_ID=populate_Defense_tools('Ubuntu_Suricata_ET',con)
    Defense_tools_ID=6
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("Ubuntu_Suricata_ET",'U_Suricata_ET',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_Ubuntu_Suricata_ET) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handle=reading_pcap_files(local_directory_Input_data) 
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)
   

    print "Processing FreeBSD_Snort_Com Data............"
    #Defense_tools_ID=populate_Defense_tools('FreeBSD_Snort_Com',con)
    Defense_tools_ID=7
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("FreeBSD_Snort_Com",'F_Snort_Com',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_FreeBSD_Snort_Com) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handle=reading_pcap_files(local_directory_Input_data) 
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)

    print "Processing FreeBSD_Snort_Reg Data............"
    #Defense_tools_ID=populate_Defense_tools('FreeBSD_Snort_Reg',con)
    Defense_tools_ID=8
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("FreeBSD_Snort_Reg",'F_Snort_Reg',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_FreeBSD_Snort_Reg) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handle=reading_pcap_files(local_directory_Input_data)
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)

    print "Processing FreeBSD_Suricata_ET Data............"
    #Defense_tools_ID=populate_Defense_tools('FreeBSD_Suricata_ET',con)
    Defense_tools_ID=9
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("FreeBSD_Suricata_ET",'F_Suricata_ET',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_FreeBSD_Suricata_ET) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handle=reading_pcap_files(local_directory_Input_data) 
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)
    
    print "Processing CentSnortCommunity Data............"
    #Defense_tools_ID=populate_Defense_tools('Centos_Snort_Com',con)
    Defense_tools_ID=10
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("CentSnortCommunity",'C_Snort_Com',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_CentOS_Snort_Com) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handle=reading_pcap_files(local_directory_Input_data) 
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)
    
    print "Processing CentSnortReg Data............"
    #Defense_tools_ID=populate_Defense_tools('Centos_Snort_Reg',con)
    Defense_tools_ID=11
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("CentSnortReg",'C_Snort_Reg',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_CentOS_Snort_Reg)
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handle=reading_pcap_files(local_directory_Input_data) 
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)

    print "Processing CentosSuricataET Data............"
    #Defense_tools_ID=populate_Defense_tools('Centos_Suricata_ET',con)
    Defense_tools_ID=12
    mysql_Data1, mysql_Data2, mysql_Data3 =mysql_database_query("CentosSuricataET",'CentSuricataET',"D3Sepsrccity")
    cap,File_handler=reading_pcap_files(local_directory_CentOS_Suricata_ET) 
    List_of_Packet_headers=populating_tables(cap,File_handler,mysql_Data1,mysql_Data2,mysql_Data3, Defense_tools_ID,Detection_ID1,Detection_ID2,con)
    Combined_list_of_Packets= Combined_list_of_Packets+List_of_Packet_headers
    cap,File_handle=reading_pcap_files(local_directory_Input_data) 
    temp,Input_packet_headers=packet_tracing_from_input_to_output(cap,File_handler,List_of_Packet_headers,Defense_tools_ID,con)
    print len(temp)  

    print "Processing Input Data............"   
#   Defense_tools_ID=populate_Defense_tools('Input',con)
    Defense_tools_ID=13
    temp=packet_tracing_from_output_to_input(Input_packet_headers,Combined_list_of_Packets,Defense_tools_ID,con)
    print len(temp)  
    con.close()
    tim_elapsed=(time.clock()- time_start)
    print "Computation time", tim_elapsed

    
    



       

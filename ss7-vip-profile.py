import sys, csv, os

def user_profile(in_file_path, out_file_path, imsi):
  in_file = open(in_file_path, 'rb')
  out_file = open(out_file_path, 'wb')

  csv_reader = csv.reader(in_file, delimiter=',', quotechat='"')
  csv_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

  #header = "no,time_epoch,opc,dpc,length,map.message,sccp.calling.digits,sccp.calling.ssn,sccp.called.digits,sccp.called.ssn,imsi,msisdn,new_area,lac"

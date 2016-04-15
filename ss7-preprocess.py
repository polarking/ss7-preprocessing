#!/usr/bin/python
# Simple script to pre-process an SS7 network capture.
# Input: Wireshark/tshark pcap file
# Output: Dechunked csv file


import sys, csv, os, subprocess
from datetime import datetime, timedelta


def sctpdechunk(working_dir, in_file_path, out_file_path):
  perl_script = working_dir + "/sctpdechunch.perl"
  subprocess.call(["perl", perl_script, in_file_path, out_file_path])


def pcap_to_csv(in_file_path, out_file_path):
  subprocess.call("""tshark -r {0} -Y gsm_map -T fields \
    -e _ws.col.No. \
    -e frame.time_relative \
    -e m3ua.protocol_data_opc \
    -e m3ua.protocol_data_dpc \
    -e _ws.col.Length \
    -e _ws.col.Info \
    -e sccp.calling.digits \
    -e sccp.calling.ssn \
    -e sccp.called.digits \
    -e sccp.called.ssn \
    -e gsm_map.imsi \
    -e gsm_map.ms.imsi \
    -e gsm_map.ch.imsi \
    -e gsm_map.sm.imsi \
    -e gsm_map.om.imsi \
    -e gsm_map.address.digits \
    -e gsm_map.tbcd_digits \
    -e gsm_map.ms.msc_Number \
    -e gsm_map.ms.lac \
    -E header=y \
    -E separator=, \
    -E quote=d \
    -E occurrence=f > {1}""".format(in_file_path, out_file_path), shell=True)


def column_merge(in_file_path, out_file_path, time_diff):
  row_num = 0
  in_file = open(in_file_path, 'rb')
  out_file = open(out_file_path, 'wb')

  num_lines = sum(1 for line in open(in_file_path, 'rb'))

  csv_reader = csv.reader(in_file, delimiter=',', quotechar='"')
  csv_reader_ahead = csv.reader(in_file, delimiter=',', quotechar='"')
  csv_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

  header = "no,timestamp,opc,dpc,length,map.message,sccp.calling.digits,sccp.calling.ssn,sccp.called.digits,sccp.called.ssn,imsi,msisdn,new_area,lac"

  csv_writer.writerow(header.split(','))

  # Skip read header
  csv_reader.next()

  # One reader ahead to read time diffs
  csv_reader_ahead.next()
  csv_reader_ahead.next()

  base_time = datetime(2016, 1, 1, 0, 0, 0) # 1.1.2016 00:00:00

  for row in csv_reader:
    imsi_merged = ""
    msisdn_merged = ""

    imsi = str(row[10])
    imsi_ms = str(row[11])
    imsi_ch = str(row[12])
    imsi_sm = str(row[13])
    imsi_om = str(row[14])

    msisdn = str(row[15])

    tbcd_digits = str(row[16])
    new_area = str(row[17])
    lac = str(row[18])

    if lac != "":
      lac = lac.split(':')
      lac = lac[0] + lac[1]
      lac = int(lac, 16)

    if imsi != "" or imsi_ms != "" or imsi_ch != "" or imsi_sm != "" or imsi_om != "":
      imsi_merged = tbcd_digits

    if msisdn != "":
      msisdn_merged = msisdn
      msisdn_merged = msisdn.split(',')
      for num in msisdn_merged:
        if num.startswith('47'):
          msisdn_merged = num
        elif num.startswith('46'):
          msisdn_merged = num 
        else:
          msisdn_merged = ""

    #if msisdn_merged != "":
    #  msisdn_merged = msisdn_merged.split(':')
    #  msisdn_merged = msisdn_merged[1][::-1] + msisdn_merged[2] + msisdn_merged[3] + msisdn_merged[4][::-1]

    if new_area == "91:11:11:11:11":
      new_area = "1"
    elif new_area == "91:22:22:22:22":
      new_area = "2"
    elif new_area == "91:33:33:33:33":
      new_area = "3"

    time = row[1]
    time_shift = float(time) / float(time_diff)

    if row_num < (num_lines - 2):
      next_row = csv_reader_ahead.next()
    else:
      next_row = []

    if next_row:
      time_next = next_row[1]
      time_next = float(time_next) / float(time_diff)
      message_time_diff = time_next - time_shift
    else:
      message_time_diff = time_shift - float(time)

    time_delta = timedelta(0, message_time_diff)
    base_time = base_time + time_delta

    new_row = row_num, base_time.__str__(), row[2], row[3], row[4], row[5].strip(), row[6], row[7], row[8], row[9], imsi_merged, msisdn_merged, new_area, lac

    csv_writer.writerow(new_row)

    row_num += 1


  in_file.close()
  out_file.close()


def get_last_row(csv_file_path):
  with open(csv_file_path, 'rb') as f:
    reader = csv.reader(f)
    num_lines = reader.line_num
    lastline = reader.next()
    for line in reader:
      lastline = line
    return (lastline, num_lines)


def read_time_values(out_file_path):
  lastline, num_lines = get_last_row(out_file_path)
  time_max = lastline[1]
  month_sec = 2678400
  diff = float(time_max) / float(month_sec)
  return diff


if not len(sys.argv) > 2:
  exit("No command line arguments provided")


in_file_path = str(sys.argv[1])
out_file_path = str(sys.argv[2])

working_dir = os.path.dirname(os.path.realpath(__file__))

dechunk_file = in_file_path + ".dechunk.pcap"
csv_file = in_file_path + ".csv"

sctpdechunk(working_dir, in_file_path, dechunk_file)
pcap_to_csv(dechunk_file, csv_file)
time_diff = read_time_values(csv_file)
column_merge(csv_file, out_file_path, time_diff)

os.remove(dechunk_file)
os.remove(csv_file)


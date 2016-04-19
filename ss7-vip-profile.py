#!/usr/bin/python


import sys, csv, os, math
from datetime import datetime,timedelta


lac_distances = {
  "8138-8161": 12,
  "8161-8161": 12,
  "8161-8189": 8,
  "8161-9321": 14,
  "8189-9321": 9,
  "9321-9343": 15,
  "9343-9385": 3,
  "6593-8138": 281,
  "6593-8161": 337,
  "6593-8189": 521,
  "6593-9321": 287,
  "6593-9343": 137,
  "6593-9385": 198,
  "6593-6593": 50,
}


def user_profile(in_file_path, out_file_path):
  in_file = open(in_file_path, 'rb')
  out_file = open(out_file_path, 'wb')

  csv_reader = csv.reader(in_file, delimiter=',', quotechar='"')
  csv_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

  #header = "no,timestamp,opc,dpc,length,map.message,sccp.calling.digits,sccp.calling.ssn,sccp.called.digits,sccp.called.ssn,imsi,msisdn,new_area,lac"
  header = "no,timestamp,length,distance_traveled,last_update"
  csv_writer.writerow(header.split(','))

  subscriber_imsi = "24201111111110"
  map_update_location = "invoke updateLocation"
  row_counter = 0

  last_update = None
  last_lac = None

  csv_reader.next() # Skip header

  for row in csv_reader:
    row_num = row[0]

    try:
      timestamp = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
      timestamp = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")

    opc = row[2]
    dpc = row[3]
    byte_length = row[4]
    map_message = row[5]
    cggt = row[6]
    cdgt = row[8]
    imsi = row[10]
    msisdn = row[11]
    new_area = row[12]
    new_lac = row[13]

    new_row = []

    if map_message == map_update_location and imsi == subscriber_imsi:
      new_row.append(row_counter)
      new_row.append(timestamp.__str__())
      new_row.append(byte_length)

      if last_lac is None:
        last_lac = new_lac

      new_row.append(lac_distance(last_lac,new_lac))

      if last_update is None:
        last_update = timestamp

      new_row.append((timestamp - last_update).total_seconds())

      csv_writer.writerow(new_row)

      last_update = timestamp
      last_lac = new_lac

      row_counter += 1

  in_file.close()
  out_file.close()


def lac_distance(lac_a, lac_b):
  if lac_a > lac_b:
    t = lac_a
    lac_a = lac_b
    lac_b = t

  lac_distance_val = str(lac_a) + "-" + str(lac_b)
  return lac_distances[lac_distance_val]


if not len(sys.argv) > 2:
  exit("No command line arguments provided")


in_file_path = str(sys.argv[1])
out_file_path = str(sys.argv[2])

user_profile(in_file_path, out_file_path)


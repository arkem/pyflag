import pyflag.Reports as Reports
import pyflag.Graph
import socket, struct
import pyflag.DB as DB
from pyflag.MatlibPlot import LinePlot
from collections import Counter
import pyflag.FileSystem as FileSystem

def resolve_inodes(case, inode_list):
    inodes = set()
    inode_str = set()
    for i in inode_list:
        if "|S" not in i:
            try:
                inodes.add(int(i))
            except ValueError:
                pass
        else:
            inode_parts = i.split("|")
            for i, p in enumerate(inode_parts):
                if p.startswith("S"):
                    if "/" not in p:
                        inode_str.add("|".join(inode_parts[:i+1]))
                    else:
                        streams = p.split("/")
                        inode_str.add("|".join(inode_parts[:i]) \
                                          + "|" + streams[0])
                        inode_str.add("|".join(inode_parts[:i]) \
                                          + "|S" + streams[1])
    if inode_str:
        dbh = DB.DBO(case)
        dbh.execute("select inode_id from inode where inode in ('%s')", "','".join(inode_str))
        for row in dbh:
            inodes.add(row["inode_id"])

    return inodes

class IPIDPlot(Reports.report):
    name = "IPIDPlot"
    family = "Network Forensics"

    parameters = {"inode_list": "sqlsafe",\
                  "src_ip": "sqlsafe",\
                  "time_off": "numeric",\
                  "y_axis": "string",\
                  "x_axis": "string"
                 }

    def form(self, query, result):
        src_list = Counter()
        if query.has_key("inode_list") and query.has_key("case"):
            inodes = set()
            inode_list = [x.strip() for x in query["inode_list"].split(',')[:5000]]
            if len(inode_list) >= 5000:
                result.text("More than 5000 inodes selected, not all of them will be plotted")

            inodes = resolve_inodes(query["case"], inode_list)

            if inodes:
                dbh = DB.DBO(query["case"])
                sql = "select src_ip from connection_details where inode_id in (%s);"\
                      % ", ".join([str(x) for x in inodes])
                dbh.execute(sql)
                for r in dbh:
                    src_list[r["src_ip"]] += 1
                del query["inode_list"]
                query["inode_list"] = ",".join([str(x) for x in inodes])
        
        result.case_selector()
        result.defaults = query
        result.textfield('Inodes', 'inode_list') 
        result.textfield('Extra minutes around the sessions:', 'time_off')

        result.const_selector('Y Axis Value:',\
                              'y_axis',\
                              ["ipid", "ipid_minus_tcp_ts", "tcp_ts"],\
                              ["IPID", "IPID no tcp_ts", "TCP tsval"])

        result.const_selector('X Axis Value:',\
                              'x_axis',\
                              ["packet", "time"],\
                              ["Packet Number", "Timestamp"])

        if src_list:
            # output a selection widget
            result.const_selector("Source IP Addresses",\
                                  "src_ip",\
                                  [x[0] for x in src_list.most_common()],\
                                  ["%r (%r)" % (socket.inet_ntoa(struct.pack(">I", x[0])), x[1])\
                                    for x in src_list.most_common()])


    def display(self, query, result):
        result.heading("IPID Plot")
        dbh = DB.DBO(query["case"])
        inodes = resolve_inodes(query["case"], query["inode_list"].split(","))
        inodes = ",".join([str(x) for x in inodes])

        if query["y_axis"] == "ipid":
            y_axis = ("ipid as y_axis", "AND ipid IS NOT NULL")
        if query["y_axis"] == "ipid_minus_tcp_ts":
            y_axis = ("ipid as y_axis", "AND ipid IS NOT NULL AND tcp_ts IS NULL AND connection_details.type = 'tcp'")
        if query["y_axis"] == "tcp_ts":
            y_axis = ("tcp_ts as y_axis", "AND tcp_ts IS NOT NULL")

        if query["x_axis"] == "time":
            x_axis = "UNIX_TIMESTAMP(pcap.ts_sec) as x_axis"
        else:
            x_axis = "id as x_axis"

        # get all packets from the current stream
        # query is untrusted user data and we should not use it to build queries
        # however this is a common pattern in pyflag so we're pretty screwed anyway
        sql = "select %s, %s from `connection` INNER JOIN (`pcap`, `connection_details`) on packet_id = id and connection.inode_id = connection_details.inode_id where connection.inode_id IN (%s) AND src_ip = %s %s" % (x_axis, y_axis[0], inodes, query["src_ip"], y_axis[1])
        dbh.execute(sql)

        session_data = ([], [])
        for row in dbh:
            print row['x_axis'], row['y_axis']
            session_data[0].append(row['x_axis'])
            session_data[1].append(row['y_axis'])

        # get the start and end times for the stream and widen the interval by 15 minutes
        dbh.execute("select DATE_ADD(max(pcap.ts_sec), INTERVAL %s MINUTE) as max, DATE_SUB(min(pcap.ts_sec), INTERVAL %s MINUTE) as min from `connection` INNER JOIN (`pcap`, `connection_details`) on packet_id = id and connection.inode_id = connection_details.inode_id where connection.inode_id IN (%s) and src_ip = %s", (query["time_off"], query["time_off"], inodes, query["src_ip"]))
        row = dbh.fetch()
        session_max = row["max"]
        session_min = row["min"]

        source_ip = query["src_ip"]

        # get all the packets from this source ip during the interval
        dbh.execute("select %s, %s from `pcap` INNER JOIN (`connection`, `connection_details`) on connection.inode_id = connection_details.inode_id and connection_details.reverse IS NOT NULL and connection.packet_id = id WHERE src_ip = %r and pcap.ts_sec < %r and pcap.ts_sec > %r %s", (x_axis, y_axis[0], source_ip, session_max, session_min, y_axis[1]))

        other_data = ([], [])
        for row in dbh:
            other_data[0].append(row['x_axis'])
            other_data[1].append(row['y_axis'])

        lp = LinePlot()

        if not query.has_key("download"):
            lp.plot(zip(other_data[0], other_data[1]),\
                    query, result,\
                    {'timestamp': query["x_axis"] == "time", 'figsize': (12, 8)},\
                    {'color': '0.75'},\
                    zip(session_data[0], session_data[1]))
            download = query.clone()
            download.default('download', True)
            result.toolbar(link = download, icon = "filesave.png", tooltip = "Download Plot", pane="self")

            other_x_axis = query.clone()
            if other_x_axis.has_key("x_axis"):
                if other_x_axis["x_axis"] == "time":
                    del(other_x_axis["x_axis"])
                    other_x_axis["x_axis"] = "packet"
                else:
                    del(other_x_axis["x_axis"])
                    other_x_axis["x_axis"] = "time"
            else:
                other_x_axis["x_axis"] = "time"
            result.toolbar(link = other_x_axis, icon = "clock.png",\
                           tooltip = "Change X axis to %s" % other_x_axis["x_axis"],\
                           pane="self")
        else:
            lp.plot(zip(other_data[0], other_data[1]), query, result,\
                    {'timestamp': query["x_axis"] == "time", 'figsize': (20, 15)},\
                    {'markersize': 8, 'color': '0.75'}, zip(session_data[0], session_data[1]))


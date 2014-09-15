# Author: @mcc0rm4ck aka @crankyflamingo
# tvproxy v0.1 - a POC traffic proxy you can use to watch tv from
# outside the country to bypass restrictions.
# Not all data is streamed via the proxy, just DNS & initial connections
# that determine locale.
# Requires a machine inside the country to proxy some traffic off.
# Easiest way is to create an Azure/AWS free tier.
# Runs a DNS, HTTPS and HTTP (not actually used) proxy
# The DNS is to prevent GeoDNS lookups, and the HTTPS is for the initial
# connections
# You set your home router to point to the sever you've created running
# this script.
#
# This should work for a variety of tv sites.
#
# For faster DNS queries, consider running a local dnsmasq instance and
# simply setting the following option in the /etc/dnsmasq.conf file:
# server=/netflix.com/<IP address of proxy server>
#

import socket
import dnslib
import re
from thread import start_new_thread
import copy
from time import sleep

HOST = ''   # listens on all interfaces
UPSTREAM_DNS = '8.8.4.4'

# defines regex for the sites that need proxying
site_intercepts = ['.*\.netflix\.com', ]

# This dict will hold the mapping of domains to real IP addresses
# NOTE: Pre-adding sites to this list is only for the case where clients
# have the DNS of your proxy server cached already. Simply waiting or
# clearing the cache makes pre-populating this list unecessary, because
# we now intercept based on regex instead. Keeping for posterity or corner
# cases I've not considered.
site_routes = {}

# Win8 metro app
site_routes['cbp.nccp.netflix.com'] = ''
site_routes['secure.netflix.com'] = ''
site_routes['ichnaea.netflix.com'] = ''
site_routes['nmtracking.netflix.com'] = ''
site_routes['www.netflix.com'] = ''
# Roku app
site_routes['appboot.netflix.com'] = ''
site_routes['nrdp.nccp.netflix.com'] = ''
site_routes['api-global.netflix.com'] = ''
site_routes['index.ehub.netflix.com'] = ''
# website
site_routes['pr.netflix.com'] = ''
site_routes['presentationtracking.netflix.com'] = ''
site_routes['api-us.netflix.com'] =''
site_routes['cbp-us.nccp.netflix.com'] = ''
# IOS and ChromeCast
site_routes['ios.nccp.netflix.com'] = ''
site_routes['uiboot.netflix.com'] = ''
site_routes['nccp-nrdp-31.cloud.netflix.net'] = ''
site_routes['android.nccp.netflix.net'] = ''
site_routes['nrdp.nccp.netflix.net'] = ''
site_routes['htmltvui-api.netflix.com'] = ''

PROXY_HOST_IP = '192.168.0.1'   # This is the external IP of the proxy

site_throughput = {}    # Track data to sites for potential triaging

def get_a_record(records):
  """
  Parses all returned records from an existing lookup for an
  A record (IP)
  """
  for rec in records.rr:
    if rec.rtype == 1:
      return rec.rdata

def get_domain_a_record(domain):
  """
  Gets a record for a given domain name
  """
  dns = dnslib.DNSRecord()
  dns.add_question(dnslib.DNSQuestion(domain))
  resp = dns.send(UPSTREAM_DNS)
  resp_obj = dnslib.DNSRecord.parse(resp)
  return str(get_a_record(resp_obj))

def dns_handler(data, addr, sock):
  """
  Functions as a standard DNS server for non-interesting domains.
  Modifies interesting domains to point to the proxy server.
  """

  request = dnslib.DNSRecord.parse(data)
  if not request:
    return

  proxy = dnslib.DNSRecord()
  proxy.questions = request.questions
  proxy.header.id = request.header.id
  response = proxy.send(UPSTREAM_DNS)

  # save and update the intercept IP. Potentially Necessary because
  # TV sites rotate DNS entries for load balancing
  for site in site_intercepts:
    if site.match(str(request.q.qname)):
      print 'Intercepting DNS request for ', str(request.q.qname)

      resp_obj = dnslib.DNSRecord.parse(response)
      ##netflix_map[str(request.q.qname)] = get_a_record(resp_obj)

      site_routes[str(request.q.qname).rstrip('\.')] \
        = str(get_a_record(resp_obj))

      resp_obj.rr  = []
      resp_obj.add_answer(*dnslib.RR.fromZone(str(request.q.qname) \
                                              +" A " + PROXY_HOST_IP))
      response = dnslib.DNSRecord.pack(resp_obj)
    else:
      print 'Ignoring:', request.q.qname

  sock.sendto(response, addr)

def update_throughput(domain, bytes_):
  global site_throughput
  site_throughput.setdefault(domain, 1)
  site_throughput[domain] = site_throughput[domain] + bytes_

def display_throughput():
  while True:
    print ' '
    for domain, bytes_ in site_throughput.items():
      print 'Transferred %.2fMb to/from %s' % (bytes_/(1024*1024), domain)
    sleep(60*60*3)

def mitm_proxy(port=443):
  '''
  Listens on the supplied port for connections, invokes proxy for each
  one
  '''
  print '\nmitm proxy starting on %s' % port
  mitm = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
  mitm.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  mitm.bind(('', port))
  mitm.listen(10)
  start_new_thread(display_throughput, ())

  while True:
    sock, addr = mitm.accept()
    start_new_thread(connection_forward, (sock, port))

def data_pipe(src, dst, skip, indata, domain):
  '''
  shuttles data back and forth between host and dest.
  skip and indata are for the initial connection attempt where we had
  to peek at the incoming data to match the intended domain (HTTP(S) GET
  or POST has the domain in the header, even on with SSL this still
  works
  '''
  bytes_ = 0
  while True:
    if skip:
      data = indata
      skip = False
    else:
      data = src.recv(4096)

    if not data:
      break
    dst.send(data)
    bytes_ += len(data)

  update_throughput(domain, bytes_)

def get_conn_ip(data):
  '''
  looks in initial data request (HTTP GET/POST) to match the intended
  destination, and returns the right IP
  '''
  for ni in site_routes:
    if ni in data:
      return (ni, site_routes[ni])

def connection_forward(src, port):
  '''
  on connect, this sets up data_pipes between source and dest
  '''
  # interestingly enough, things go badly if you don't copy the data
  # to a different buffer, even though there is no modifying going on
  data = src.recv(4096)
  test = copy.deepcopy(data)
  (domain, netflix_ip) = get_conn_ip(test)

  print 'Connection to %s:%s, proxying to %s' % (domain, port, netflix_ip)

  # create connection to real netflix IP
  dst = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
  dst.connect((netflix_ip, port))

  # shuttle data back and forth
  start_new_thread(data_pipe, (src, dst, True, data, domain))
  start_new_thread(data_pipe, (dst, src, False, None, domain))

def main():

  # create DNS server
  udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_sock.bind((HOST,54))

  global site_routes
  global site_intercepts

  # Compile up regexes for matching
  for site in site_intercepts:
    try:
      site_re = re.compile(site)
      site_intercepts.remove(site)
      site_intercepts.append(site_re)
    except Exception, ex:
      print 'Problem with regex. Bailing.'
      return

  # Prepopulate intercept IPs in the case of cached dns on the client
  # As mentioned above, this is largely uncecessary.
  for k in site_routes.keys():
    site_routes[k] = get_domain_a_record(k)

  print 'Intercepting:'
  print site_routes

  #TODO: keep track of traffic kb to/from sites

  # set up transparent HTTPS + HTTP proxy
  start_new_thread(mitm_proxy, (443,))
  start_new_thread(mitm_proxy, (80,))

  print '\nListening for DNS queries, will redirect where necessary'
  while True:
    #new_sock, address = udp_sock.accept()
    data, addr = udp_sock.recvfrom(4096)
    start_new_thread(dns_handler,(data, addr, udp_sock))

if __name__ == '__main__':
  main()

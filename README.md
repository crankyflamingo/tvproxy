tvproxy
=======

POC to proxy selected traffic for TV or similar service via a server running the code, in order to bypass outside US (or other country) restrictions.

Created because I was uncomforable with the idea of the existing services (unblockus et al.) being my dns providers.
Runs minimal DNS interception server and TCP proxies for on ports 443 and 80 for HTTP(S).

Sites to intercept are chosen by regex. It's important to note that not all sites need to be intercepted, particularly not those streaming content. Intercepting these will make the connection slow. Only the servers that handle the authentication, in most cases, need to be proxied.

Designed to be run on cloud hosted VM inside the country you wish to view content. This can be achieved by creating a free-tier AWS or Azure account and running a VM in the country you wish to have TV in.

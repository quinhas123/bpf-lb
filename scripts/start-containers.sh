docker run -d --rm --name backend-A --mac-address 02:42:ac:11:00:02 -h backend-A --env TERM=xterm-color nginxdemos/hello:plain-text
docker run -d --rm --name backend-B --mac-address 02:42:ac:11:00:03 -h backend-B --env TERM=xterm-color nginxdemos/hello:plain-text
#sudo docker run -d --rm -it --name client --mac-address 02:42:ac:11:00:04 -h client --env TERM=xterm-color client
#sudo docker run --rm -it --privileged -h lb --name lb --mac-address 02:42:ac:11:00:05 --env TERM=xterm-color lb

#docker run -d --name server-2 -h server-2 -p 81:8000 http-server uv run --script simple-http-server.py -i 2
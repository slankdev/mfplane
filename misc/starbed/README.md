# StarBED

## Constructing management node

```
export https_proxy="http://proxy1:8080/"
export http_proxy="http://proxy1:8080/"
export ftp_proxy="http://proxy1:8080/"
curl https://pyenv.run | bash
pyenv install 3.10
```

```
curl -L get.docker.com | sudo sh -xe
sudo mkdir -p /etc/systemd/system/docker.service.d
cat <<EOF | sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf
[Service]
Environment="HTTP_PROXY=http://proxy1:8080/"
EOF
sudo systemctl daemon-reload
sudo systemctl restart docker
```

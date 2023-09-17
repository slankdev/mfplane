# StarBED

## Constructing management node

```
#ssh starbed-w001
ssh starbed-w012
```

```
vim ~/.bash_profile

. ~/.bashrc
```

```
vim ~/.bashrc

export https_proxy="http://${IPADDR}:8080/"
export http_proxy="http://${IPADDR}:8080/"
export HTTPS_PROXY="http://${IPADDR}:8080/"
export HTTP_PROXY="http://${IPADDR}:8080/"
export PATH=$PATH:/usr/local/go/bin
export EDITOR=vim
export KUBECONFIG=/home/staruser/mfplane.kind.kubeconfig.yaml

alias gb='git branch'
alias gs='git status'
alias gl='git log --pretty=format:" %h  %s %d"'
alias ga='git add'
alias gd='git diff'
alias gc='git commit'
alias gco='git commit -m'
alias gca='git commit --amend'
alias gce='git commit -m  "`date +%Y.%m.%d-%H:%M`"'
alias gdo="git diff origin/\$(git symbolic-ref --short HEAD)"
```

```
curl https://pyenv.run | bash
vim ~/.bashrc

export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
```

```
pyenv install 3.9 && pyenv global 3.9
pip install pipenv
```

```
export GITHUB_USER=slankdev
export GITHUB_PAT=****
git clone https://$GITHUB_USER:$GITHUB_PAT@github.com/slankdev/mfplane ~/mfplane
cd ~/mfplane/misc/starbed
pipenv sync && pipenv run ansible-playbook -c local devops.yaml
```

```
vim ~/.bashrc

export ANSIBLE_SSH_USER=****
export ANSIBLE_SSH_PASS=****
export ANSIBLE_SUDO_PASS=****
```

## Constructing mfplane environment

```
pipenv run ansible-playbook main.yaml
```

```
export STARBED_ENDPOINT=http://*****
export STARBED_USERNAME=*****
export STARBED_PASSWORD=*****
```

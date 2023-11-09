## Installing
-------------------------------------------------------

### Import the MongoDB GPG key
wget -qO - https://www.mongodb.org/static/pgp/server-4.0.asc | sudo apt-key add -

### Add the MongoDB repository
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -sc)/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list

### Update package lists
sudo apt update

### Install MongoDB
sudo apt install -y mongodb-org=4.0.9


### Create directories for data and log files for each MongoDB node:
--------------------------------------------------------
sudo mkdir -p /data/db/node1 /data/db/node2 /data/db/node3
sudo mkdir -p /var/log/mongodb/node1 /var/log/mongodb/node2 /var/log/mongodb/node3


### Run each node separately on the specified ports:
--------------------------------------------------------

mongod --port 27017 --dbpath /data/db/node1 --logpath /var/log/mongodb/node1/mongod.log --replSet rs0 --fork

mongod --port 27018 --dbpath /data/db/node2 --logpath /var/log/mongodb/node2/mongod.log --replSet rs0 --fork

mongod --port 27019 --dbpath /data/db/node3 --logpath /var/log/mongodb/node3/mongod.log --replSet rs0 --fork

## Initialize the replica set. Connect to one of the nodes, for example, the one running on port 27017:
--------------------------------------------------------
mongo --port 27017

### In the MongoDB shell, run the following commands to initiate the replica set:


```
rs.initiate({
  _id: 'rs',
  members: [
    { _id: 0, host: 'localhost:27017' },
    { _id: 1, host: 'localhost:27018' },
    { _id: 2, host: 'localhost:27019' }
  ]
});
```


## --------------------------------------------------------------

# Import the MongoDB GPG key
wget -qO - https://www.mongodb.org/static/pgp/server-<mongodb-version>.asc | sudo apt-key add -

# Add the MongoDB repository
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu <your-ubuntu-version>/mongodb-org/<mongodb-version> multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-<mongodb-version>.list

# Update package lists
sudo apt update

# Install MongoDB
sudo apt install -y mongodb-org=<mongodb-version>


## Shutdown:

use admin
db.shutdownServer()

mongo --port 27017



## Install:
wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -

sudo vim /etc/apt/sources.list.d/mongodb-org-4.4.list

>> In vim editor
`deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.4 multiverse`

sudo apt update
sudo apt install mongodb-org=4.4.6 mongodb-org-server=4.4.6 mongodb-org-shell=4.4.6 mongodb-org-mongos=4.4.6 mongodb-org-tools=4.4.6
sudo systemctl enable mongod
sudo systemctl start mongod
sudo systemctl status mongod


mongod --port 27017 --dbpath /data/db1 --logpath /dblog/log1/mongod.log --replSet rs

mongod --port 27018 --dbpath /data/db2 --logpath /dblog/log2/mongod.log --replSet rs

mongod --port 27019 --dbpath /data/db3 --logpath /dblog/log3/mongod.log --replSet rs


## Nodejs:

tar -xf node-v18.17.1-linux-x64.tar.xz
mv node-v18.17.1-linux-x64 nodejs
sudo mv nodejs /usr/local/

echo 'export PATH=$PATH:/usr/local/nodejs/bin' | sudo tee -a /etc/profile
source /etc/profile


node -v
npm -v

## Redis:

sudo apt install redis-server
sudo vim /etc/redis/redis.conf

sudo systemctl status redis
sudo systemctl start redis
sudo systemctl enable redis

## flexi manage:

cd backend
npm install

curl -X POST -k "https://local.flexiwan.com:3443/api/users/register" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"accountName\":\"account\",\"userFirstName\":\"user\",\"userLastName\":\"lastname\",\"email\":\"user@example.com\",\"password\":\"xxxxxxxx\",\"userJobTitle\":\"eng\",\"userPhoneNumber\":\"\",\"country\":\"US\",\"companySize\":\"0-10\",\"serviceType\":\"Provider\",\"numberSites\":\"10\",\"companyType\":\"\",\"companyDesc\":\"\",\"captcha\":\"\"}"


 curl -X POST -k "https://local.flexiwan.com:3443/api/users/verify-account" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"id\":\"654538d4599e3c64624b002b\",\"token\":\"kLoCjXDohmL8vicoyPo6Gn0ELmPj6y\"}"


curl -X POST -sD - -k "https://local.flexiwan.com:3443/api/users/login" -H "accept: application/json" -H "Content-Type: application/json" -d "{\"username\":\"user1@example.com\",\"password\":\"xxxxxxxx\",\"captcha\":\"\"}"
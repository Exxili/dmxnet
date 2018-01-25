# dmxnet
ArtNet-DMX-sender and receiver for nodejs,
currently under heavy development!

## Installation

**How to install current development version:**

`npm install git+https://git@github.com/margau/dmxnet.git `

## Usage

**See example_rx.js and example_tx.js**

**Include dmxnet lib:**

`var dmxlib=require('dmxnet');`

**Create new dmxnet object:**

`var dmxnet = new dmxlib.dmxnet(options);`

Options:

```javascript
{
  verbose: 1, //Verbosity, default 0
  oem: 0 //OEM Code from artisticlicense, default to dmxnet OEM
}
```

### Transmitting Art-Net

**Create new sender object:**

`var sender=dmxnet.newSender(options);`

Options:

```javascript
{
  ip: "127.0.0.1", //IP to send to, default 255.255.255.255
  subnet: 0, //Destination subnet, default 0
  universe: 0, //Destination universe, default 0
  net: 0, //Destination net, default 0
  port: 6454 //Destination UDP Port, default 6454
}
```

**Set Channel:**

`sender.setChannel(channel,value);`

Sets channel (0-511) to value (0-255) and transmits the changed values .

**Please Note: dmxnet transmits an frame every 1000ms even if no channel has changed its value!**

**Art-Net™ Designed by and Copyright Artistic Licence Holdings Ltd**
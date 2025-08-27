#!/bin/bash

arptables-nft -A FORWARD -j DROP
arptables-nft -A OUTPUT -j DROP

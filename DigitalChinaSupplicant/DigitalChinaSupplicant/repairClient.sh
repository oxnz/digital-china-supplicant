#!/bin/sh

#  repairClient.sh
#  DigitalChinaSupplicant
#
#  Created by 云心逸 on 13-3-9.
#  Copyright (c) 2013年 云心逸. All rights reserved.

clientSRC="$1"
clientDST="/usr/local/bin/dcclient"
cp "$clientSRC" "$clientDST"
chown -R root:wheel "$clientDST"
chmod +s "$clientDST"

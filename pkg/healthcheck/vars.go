package healthcheck

import "time"

const defaultURLTestTimeout = time.Second * 2

var DelayTimeout = defaultURLTestTimeout
var RelayTimeout = defaultURLTestTimeout * 2
var SpeedTimeout = time.Second * 5
var SpeedExist = false

var DelayConn = 500
var SpeedConn = 5

# gocookie
Get Chrome's cookie of website

# Installation

This package can be installed with the go get command:

    go get github.com/donkw/gocookie

# Usage

    github.com/donkw/gocookie/cookie

	cookie, _ := gocookie.NewChromeCookie().GetCookies(".baidu.com")
	for k, v := range aa {
		fmt.Println("key=", k, ", value=", v)
	}
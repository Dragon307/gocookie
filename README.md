# gocookie
Get Chrome's cookie of website

# Installation

This package can be installed with the go get command:

    go get github.com/donkw/gocookie

# Usage

    github.com/donkw/gocookie/cookie

    // return array of cookie
    cookies, err := cookie.GetChromeCookies(".baidu.com")
    // return string of cookie
    cookieString, err := cookie.GetChromeCookiesString(".baidu.com")
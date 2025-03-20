import sys
import argparse
from struct import unpack
from time import strftime, gmtime

# creds to these two resources
# https://github.com/as0ler/BinaryCookieReader/blob/master/BinaryCookieReader.py
# https://github.com/libyal/dtformats/blob/main/documentation/Safari%20Cookies.asciidoc

# be able to parse bytes (bytestring?) from an index
class PageClass:
    def __init__(self, pageContent, pageSize):
        self.PageContent = pageContent
        self.pointer = 0
        self.pageSize = pageSize

    # fetch X bytes of data (equivalent to f.read(X))
    def fetch(self, length):
        self.pointer += length
        return self.PageContent[self.pointer-length:self.pointer]

    def setPosition(self, position):
        self.pointer = position

# poor man's strcpy
def findString(CookieObject, startPosition):
    CookieObject.setPosition(startPosition)

    searchString = ""
    searchStringChar = CookieObject.fetch(1)
    while unpack('<b',searchStringChar)[0]!=0:
        searchString=searchString+ searchStringChar.decode()
        searchStringChar=CookieObject.fetch(1)

    return searchString


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="Path to your binary cookie file", required=True)
args = parser.parse_args()

FILE_PATH = args.file

f = open(FILE_PATH, "rb")

#### File headers

# verify magic bytes are correct
magic_bytes = f.read(4)
try:
    assert magic_bytes == b"cook"
except AssertionError:
    print("Invalid Cookies.binarycookie file")

# number of total pages/ cookies
totalPages = unpack(">i", f.read(4))[0]

# size of cookies
pageSizes = []
for pageSize in range(totalPages):
    pageSizes.append(unpack('>i',f.read(4))[0])
    # print(f.tell())

# cookie names and values
pages = []
for pageSize in pageSizes:
    pages.append(f.read(pageSize))

## ensure number of pages (probably unnecesary)
try:
    assert len(pageSizes) == len(pages)
except AssertionError:
    print("Number of pages does not match length of number of page sizes")


### Page parse


for index, page in enumerate(pages):
    PageObject = PageClass(page, pageSizes[index])
    
    # page header
    try:
        assert PageObject.fetch(4) == b"\x00\x00\x01\x00"
    except AssertionError:
        print("Page header incorrect")

    ### cookie record array
    subTotalCookies = unpack('<i', PageObject.fetch(4))[0]

    cookieOffsets = []
    for subcookie in range(subTotalCookies):
        cookieOffsets.append(unpack('<i', PageObject.fetch(4))[0])
    try:
        ## page footer
        assert PageObject.fetch(4) == b"\x00\x00\x00\x00"
    except AssertionError:
        print("Page footer incorrect")

    ### Cookie record
    cookie = ''
    for offset in cookieOffsets:
        PageObject.setPosition(offset)
        cookieSize = unpack("<i", PageObject.fetch(4))[0]
        cookie = PageObject.fetch(cookieSize)

        CookieObject = PageClass(cookie, len(cookie))

        #Parse the cookie contents

        # unknown field
        _ = CookieObject.fetch(4)

        flagValues = unpack('<i',CookieObject.fetch(4))[0]

        cookieFlags = ""
        match flagValues:
            case 0:
                cookieFlags = ""
            case 1:
                cookieFlags = "Secure"
            case 4:
                cookieFlags = "HttpOnly"
            case 5:
                cookieFlags = "Secure; HttpOnly"
            case _:
                cookieFlags = "Unknown"

        # unknown field
        _ = CookieObject.fetch(4)

        urlOffset = unpack("<i", CookieObject.fetch(4))[0]
        nameOffset = unpack("<i", CookieObject.fetch(4))[0]
        pathOffset = unpack("<i", CookieObject.fetch(4))[0]
        valueOffset = unpack("<i", CookieObject.fetch(4))[0]

        # end of cookie
        _ = CookieObject.fetch(8)

        # MacOS epoch time begins from 1 Jan 2001
        expiryDateEpoch = unpack("<d", CookieObject.fetch(8))[0] + 978307200
        
        # hacky fix to stop the year being set to a ridiculous value like 4001 and crashing
        try:
            expiryDate = strftime("%a, %d %b %Y ", gmtime(expiryDateEpoch))[:-1]
        except:
            expiryDateEpoch = 2013371337
            expiryDate = strftime("%a, %d %b %Y ", gmtime(expiryDateEpoch))[:-1]

        creationDateEpoch = unpack('<d',CookieObject.fetch(8))[0] + 978307200
        creationDate = strftime("%a, %d %b %Y ", gmtime(creationDateEpoch))[:-1]
                    
        url = findString(CookieObject, urlOffset - 4)
        name = findString(CookieObject, nameOffset - 4)
        path = findString(CookieObject, pathOffset - 4)
        value = findString(CookieObject, valueOffset - 4)

        print(f"Cookie : {name}={value}; domain={url}; path={path}; expires={expiryDate}; {cookieFlags}")


/*

URL scanner similar to original dirbuster.

Copyright 2018 Yuli Stremovsky <stremovsky@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

package main

//build: go build ./urlbuster.go

import (
        "fmt"
        "sort"
        "crypto/sha256"
        "io/ioutil"
        "log"
        "net/http"
        "net/http/cookiejar"
        "net/url"
        "os"
        "strings"
)

var pages = []string{}
var cookieJar, _ = cookiejar.New(nil)
var extentions = []string{"txt", "info", "tar", "tar.gz", "tgz", "zip", "rar", "pdf", "mdb", "pdf", "db", "mat", "maq", "mdf", "mde", "accde", "accdb", "mdw", "sql", "log", "old", "backup", "db2", "sqlite", "sqlitedb", "ckp", "sqlite3", "gdb", "wdb", "dbs", "xml"}

func read_signatures(filename string) []string {
  content, err := ioutil.ReadFile(filename)
  if err != nil {
    //Do something
  }
  lines := strings.Split(string(content), "\n")
  //print(lines)
  return lines
}

func check_404(body string) int {
/*
<div class="error-container">
    <div class="error-code">404</div>
    <div class="error-text">Page not found</div>
*/
  if strings.Contains(body, "Page not found") || strings.Contains(body, "Page Not Found") {
    return 404
  }
  if strings.Contains(body, "Internal Server Error") {
    return 404
  }
  return 200
}

func check_url(host string, sig string) {
  url := host + "/" + sig
  if len(sig)> 0 && sig[:1] == "/" {
    url = host + sig
  }
  client := &http.Client{Jar: cookieJar}
  //response, err := client.Get(url)
  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    log.Print(err)
    return
  }
  req.Header.Set("Referer", host + "/")
  response, err := client.Do(req)
  if err != nil {
    log.Print(err)
    return
  }
  defer response.Body.Close()
  bodyBytes, err := ioutil.ReadAll(response.Body)
  bs := string(bodyBytes)
  status:= check_404(bs)
  if status == 200 && response.StatusCode != 404 {
    //print("!!! [", response.StatusCode, "] ", url, "\n")
    hash := sha256.Sum256([]byte(bs))
    hash2 := fmt.Sprintf("%x", hash)
    sort.Strings(pages)
    i := sort.SearchStrings(pages, hash2)
    if i < len(pages) && pages[i] == hash2 {
      //print("!!! [", response.StatusCode, "] ", url, " ", hash2)
    } else {
      print("[", response.StatusCode, "] ", url, " new ", hash2 ,"\n")
      pages = append(pages, hash2)
      if len(bs) > 200 {
        print(bs[0:200])
      } else {
        print(bs)
      }
      print("\n")
      print("-------------------\n")
    }
    return
  }
  //print("[404] "+url+"\n")
}

func main() {
  if len(os.Args) == 1 {
    print("No start url specified.\n")
    fmt.Printf("Example: %s http://google.com\n", os.Args[0])
    os.Exit(-1)
  }
  start_url := os.Args[1]
  if start_url[len(start_url)-1:] == "/" {
    start_url = start_url[:len(start_url)-1]
  }
  u, err := url.Parse(start_url)
  if err != nil {
    log.Fatal(err)
  }
  site_signatures := []string{}
  for _, h := range strings.Split(u.Host, ".") {
    for _, e := range extentions {
      new_signature := fmt.Sprintf("%s.%s", h, e)
      site_signatures = append(site_signatures, new_signature )
    }
  }
  signatures := read_signatures("./signatures.txt")
  signatures = append(site_signatures, signatures...)
  //fmt.Printf("%v", signatures)
  for _, sig := range signatures {
    check_url(start_url, sig)
  }
  print("Done\n")
}

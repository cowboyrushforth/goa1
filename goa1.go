package goa1

import "fmt"
import "sort"
import "hash"
import "crypto/hmac"
import "crypto/sha1"
import "encoding/base64"
import "net/http"
import "strings"
import "errors"
import "net/url"

type OAuthRequest struct {
  Method	    string
  URL		    string
  ConsumerKey	    string
  Token		    string
  Nonce		    string
  Timestamp	    string
  SignatureMethod   string
  Version	    string
  Signature	    string
  Callback          string
  Parameters	    map[string][]string
}

type OAuthRequestTokenReply struct {
  Token string
  TokenSecret string
  CallbackConfirmed bool
}

func ParseRequest(r *http.Request) (*OAuthRequest, error) {
  urladd := "http://"+r.Host+r.URL.String()
  idxq := strings.Index(urladd, "?")
  if idxq >= 0 {
    urladd = urladd[:idxq]
  }

  req := &OAuthRequest {
    Method: r.Method,
    URL: urladd,
    Parameters: make(map[string][]string),
  }

  for k, v := range r.Header {
    appendParam(req, k, v, false)
  }

  for k, v := range r.Form {
    appendParam(req, k, v, true)
  }

  for k, v := range r.URL.Query() {
    appendParam(req, k, v, true)
  }


  return req, nil
}

func appendParam(req *OAuthRequest, k string, value []string, add bool) {
  if len(value) == 0 {
    return
  }
  if k == "Authorization" {
    hrd := value[0][6:]
    pieces := strings.Split(hrd, ",")
    for _,x := range(pieces) {
      inner_pieces := strings.Split(x, "=")
      a_key := inner_pieces[0]
      a_val := []string{strings.Replace(inner_pieces[1], "\"", "", 2)}
      appendParam(req, a_key, a_val, false)
    }
  } else {
    switch k {
    case "oauth_timestamp":
      req.Timestamp = value[0]
    case "oauth_version":
      req.Version = value[0]
    case "oauth_signature":
      req.Signature = value[0]
    case "oauth_consumer_key":
      req.ConsumerKey = value[0]
    case "oauth_nonce":
      req.Nonce = value[0]
    case "oauth_callback":
      req.Callback = value[0]
    case "oauth_signature_method":
      req.SignatureMethod = value[0]
    case "oauth_token":
      req.Token = value[0]
    default:
      if add {
        req.Parameters[k] = value
      }
    }
  }
}

type StringSlice []string

func (arr StringSlice) Len() int {
  return len(arr)
}

func (arr StringSlice) Less(i, j int) bool {
  return arr[i] < arr[j]
}

func (arr StringSlice) Swap(i, j int) {
  v := arr[i]
  arr[i] = arr[j]
  arr[j] = v
}

func PrepareQuery(params map[string][]string, encode bool) string {
  total := len(params)
  ordered := make(StringSlice, 0, total)
  for k, _ := range params {
    ordered = append(ordered, k)
  }

  sort.Sort(ordered)

  parQry := ""
  for i := 0; i < total; i++ {
    vs := params[ordered[i]]
    for j := 0; j < len(vs); j++ {
      ik := escape(ordered[i])
      ij := escape(vs[j])
      if len(ij) > 0 {
        if len(parQry) > 0 {
          if encode {
            parQry = fmt.Sprintf("%s%%26%s%%3D%s", parQry, ik, ij)
          } else {
            parQry = fmt.Sprintf("%s&%s=%s", parQry, ik, ij)
          }
        } else {
          if encode {
            parQry = fmt.Sprintf("&%s%%3D%s", ik, ij)
          } else {
            parQry = fmt.Sprintf("&%s=%s", ik, ij)
          }
        }
      }
    }
  }
  return parQry
}

func Validate(req *OAuthRequest, clientsecret, tokensecret string) (bool, error) {
  params := make(map[string][]string)
  params["oauth_consumer_key"] = []string{req.ConsumerKey}
  params["oauth_nonce"] = []string{req.Nonce}
  params["oauth_signature_method"] = []string{req.SignatureMethod}
  params["oauth_timestamp"] = []string{req.Timestamp}
  params["oauth_token"] = []string{req.Token}
  params["oauth_version"] = []string{req.Version}
  params["oauth_callback"] = []string{req.Callback}

  for k, v := range req.Parameters {
    params[k] = v
  }

  parQry := PrepareQuery(params, true)
  query := fmt.Sprintf("%s&%s%s", req.Method, escape(req.URL), parQry)

  key := fmt.Sprintf("%s&%s", escape(clientsecret), escape(tokensecret))
  sigbytes, err := sign(key, query, req.SignatureMethod)
  if err != nil {
    return false, err
  }

  signature := escape(base(sigbytes))

  return signature == req.Signature, nil
}

func RequestTokenPayload(reply * OAuthRequestTokenReply) string {
  params := make(map[string][]string)
  params["oauth_token"] = []string{reply.Token}
  params["oauth_token_secret"] = []string{reply.TokenSecret}
  parQry := PrepareQuery(params, false)
  if reply.CallbackConfirmed {
    parQry = parQry + "&oauth_callback_confirmed=true"
  } else {
    parQry = parQry + "&oauth_callback_confirmed=false"
  }
  return parQry
}

func sign(key string, str string, method string) ([]byte, error) {
  var hash hash.Hash


  if method == "HMAC-SHA1" {
    hash = hmac.New(sha1.New, []byte(key))
  } else {
    return nil, errors.New(fmt.Sprintf("Unsupported signature method: %s", method))
  }

  hash.Write([]byte(str))

  return hash.Sum(nil), nil
}

func base(data []byte) string {
  return base64.StdEncoding.EncodeToString(data)
}

func escape(str string) string {
  str = url.QueryEscape(str)
//  str = strings.Replace(str, ":", "%3A", -1)
 // str = strings.Replace(str, "/", "%2F", -1)
  return str
}

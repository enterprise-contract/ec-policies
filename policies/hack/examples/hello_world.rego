
package examples.hello_world

default allow = false

allow {
  input.msg == "hello world"
}

allow {
  input.msg == "hi there"
}

---
layout: default
title:  "Zeruel Devlog 1"
date:   2024-07-13 22:45:45 -0600
categories: jekyll update
---

You can find the code for this project [here](https://github.com/handle1337/zeruel)

# Zeruel Devlog 1

Hi there! lately I have been working on a personal project I had the idea for some years ago. I thought it would be a good exercise since I'm getting back into software development and cybersecurity to try and finish a Burpsuite-like tool I've always wanted to make. Zeruel Proxy.

The idea is simple, create a proxy capable of intercepting, modifying, and repeating requests on the fly. All through a simple GUI.

I had already written a good portion of the GUI using `tkinter` some years ago. So all that was left to do was write the proxy and the logic between the 2.

## Proxy

Writing an HTTP MITM proxy to serve the aforementioned purpose is quite straight forward.

When writing the proxy I decided to use sockets, admittedly I could've probably used some sort of wrapper like [http.server](https://docs.python.org/3/library/http.server.html) to make my life easier but I like a challenge! 

### HTTP

First thigns first, let's setup our proxy server to capture and forward our requests to the remote server.

{% highlight python %}
    def run(self):
        self.running = True
        try:

            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                         1)  # This is a necessary step since we need to reuse the IP/port immediately
            self.proxy_socket.bind((self.host, self.port))
            self.proxy_socket.listen(10)
            print(f"{self.proxy_socket}")
        except KeyboardInterrupt:
            self.stop()
            sys.exit(1)
        except socket.error as e:
            print(e)
            self.stop()
        self.handle_client()
{% endhighlight %}

In the code above a socket is created and it's options are set so that it can be reused for new socket bindings rapidly,
then it is bound to `127.0.0.1` and the desired port, I've decided to default the port to `7121` for Zeruel.

If no exceptions are raised then `handle_client()` is called.

First the proxy must accept incoming connections from the browser

{% highlight python %}
    def handle_client(self):

        while self.running:
            print(f"Intercepting: {self.intercepting}")
            print("Awaiting connection from client")
            try:
                self.client_socket, client_address = self.proxy_socket.accept()
                print(f"{self.client_socket} {client_address[0]} {client_address[1]}")
            except socket.timeout:
                print("Connection timeout, retrying...")
                continue
            except Exception as e:
                print(e)
                self.stop()
{% endhighlight %}


If a connection is succesfully achieved the proxy can begin to receive data through the new socket through which the server can communicate with the client, while the old socket stays open listening for new connections.

{% highlight python %}
            try:
                self.client_data = self.client_socket.recv(self.buffer_size)
                request = self.parse_data(self.client_data)

                if request:
                    send_data_thread = Thread(target=self.send_data, args=(request["host"],
                                                                           request["port"],
                                                                           request["data"],
                                                                           request["method"]))

                    if self.intercepting:
                        # No need to capture CONNECT reqs
                        if request["method"] != "CONNECT":
                            print("\nsending to queue\n")
                            queue_manager.client_request_queue.put(self.client_data)  # we display this in the GUI
                        else:
                            send_data_thread.start()
                    else:
                        send_data_thread.start()
            except socket.error as e:
                logger.exception(f"Exception {e} | Server ID: {self.id} |\nData: {request}")
{% endhighlight %}

The received data is then passed to the parser, which returns a dictionary that is then used to forward the request to the remote server.

{% highlight python %}
    def send_data(self, hostname: str, port: int, data: bytes, method: str = None):

        try:

            remote_socket = socket.create_connection((hostname, port))

            if port == 80:

                remote_socket.sendall(data)
                while True:
                    chunk = remote_socket.recv(self.buffer_size)
                    if not chunk:
                        break
                    print(f"chunk{chunk}\n")
                    self.client_socket.send(chunk)  # send back to browser
{% endhighlight %}

In the code above a new socket is created for the remote connection, the request we got from the browser (which is passed as the `data` arg) is then forwarded to the remote host.
Then, once a response if received from the remote host, it is sent back through the client socket to the browser.

### HTTPS

HTTPS is a bit trickier since we need to be able to decrypt the incoming requests from the browser to be able to display and modify them before they're sent out as well as being able to decrypt any requests sent back from the remote target server.

To achieve this we first need to understand how HTTPS works so let's take a look.

To implement HTTP/TLS we only really need to understand these terms and ideas:

**Certificate:** A document used to prove the validity of a public key. It contains information about it's owner (also known as the subject) and a signature of the entity that has verified the certificate's contents (called the issuer).

**Certificate Authority:** A CA is an entity that stores, signs and, issues certificates. Usually browsers have a set of trusted CA certificates and will let you install certificates of your own (very important later on!)

**Public key:** This key is shared openly, it's used to encrypt data or verify a digital signature.

**Private key:** This key is to be kept secret, hence the 'Private'. it is used to decrypt data encrypted with the public key or to create a digital signature.

Whenever you visit a site using HTTPS a certificate containing a public key signed by the CA is sent to the browser. The browser then must validate the certificate by referring to its trusted CAs and their public keys.

Your browser will then, assuming the CA is trusted, create a new private key encrypted with the public key signed by the CA. 

From then on the server and browser both have this new private key, which will be used to encrypt communication between the two.

To better illustrate this process here's a simplified diagram:

![screen1]({{ site.baseurl }}/assets/lib/images/screen1.png)


### Man-In-The-Middle

The process described above is what prevents any 3rd party sniffing out requests from gathering any sensitive data from the HTTPS requests, as they can only be decrypted using the private key. But the proxy needs to be able to decrypt this data in order to modify it as well as re-encrypt it for it to be sent out to the target server.

In the case of `google.com` we would need to have access to Google CA's private key in order to:
1. Be able to even visit the site without our browser screaming at us telling us it doesn't trust our proxy because our certificate is invalid.
2. Be able to decrypt any request passing through our proxy. <br />
Suffice to say, would be quite difficult getting our hands on Google CA's private key.

However, there is one way we can circumvent all of this trouble and it's by using self-signed certificates!

Anyone can become their own CA, create key pairs, and sign certificates. It's quite simple really, this is how Zeruel's CA certificate is created using OpenSSL:

{% highlight bash %}
openssl genrsa -out zeruelCA.key 2048 # Generate private key

openssl req -new -x509 -days 3650 -key zeruelCA.key -out zeruelCA.crt -subj "/CN=zeruelproxy CA/C=US" # Create self-signed certificate
{% endhighlight %}

NOTE: If you want a more detailed guide on how to setup your own CA I highly recommend reading through this [gist](https://gist.github.com/soarez/9688998)

This new certificate can now be installed in our browser so that it is trusted and we can move on to the next challenge.

The proxy server must essentially impersonate every CA out there, which means that it needs to generate and sign certificates for each host we visit from the browser.

For that, it needs to:

- Generate a new key pair

{% highlight python %}
    def generate_keypair(path=None):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        if path:
            with open(path, 'w+') as key_file:
                key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
        return key
{% endhighlight %}
- Create a Certificate Signing Request (CSR)

{% highlight python %}
    def generate_csr(self, hostname, key, path=None):
        """
        :param hostname: Subject root hostname to use when adding SANs
        :param key: Subject's private key
        :param path: Optional path for csr request output
        :return:
        """
        san_list = [f"DNS.1:*.{hostname}",
                    f"DNS.2:{hostname}"]
        

        csr = crypto.X509Req()
        csr.get_subject().CN = hostname
        # SANs are required by modern browsers, so we add them
        csr.add_extensions([
            crypto.X509Extension(b"subjectAltName", False, ', '.join(san_list).encode())
        ])
        csr.set_pubkey(key)
        csr.sign(key, "sha256")

        if path:
            with open(path, 'w+') as csr_file:
                csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode("utf-8"))
        return csr
{% endhighlight %}

- Finally, generate the certificate


{% highlight python %}
    def generate_certificate(self, hostname: str):

        # ref: https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl

        host_cert_path = f"{self.certs_path}generated\\{hostname}"
        key_file_path = f"{host_cert_path}\\{hostname}.key"
        csr_file_path = f"{host_cert_path}\\{hostname}.csr"
        cert_file_path = f"{host_cert_path}\\{hostname}.pem"

        if not os.path.isdir(host_cert_path):
            os.mkdir(host_cert_path)

        root_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cacert, 'rb').read())
        root_ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.cakey, 'rb').read())


        key = self.generate_keypair(key_file_path)
        csr = self.generate_csr(hostname, key, csr_file_path)

        # Generate cert

        cert = crypto.X509()
        cert.get_subject().CN = hostname
        cert.set_serial_number(int.from_bytes(os.urandom(16), "big") >> 1)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)  # 1 year


        # Yes we must add the SANs to the cert as well
        san_list = [f"DNS.1:*.{hostname}",
                    f"DNS.2:{hostname}"]

        cert.add_extensions([
            crypto.X509Extension(b"subjectAltName", False, ', '.join(san_list).encode())
        ])


        # Sign it
        cert.set_issuer(root_ca_cert.get_subject())
        cert.set_pubkey(csr.get_pubkey())

        cert.sign(root_ca_key, 'sha256')

        with open(cert_file_path, 'w+') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

        return cert_file_path, key_file_path
{% endhighlight %}

The proxy is now able to generate certificates for each host dynamically and can now handle HTTPS connections between it and the browser. Because we are our own CA and have access to the private key the proxy is able to decrypt all incoming data from the browser. 

![screen2]({{ site.baseurl }}/assets/lib/images/screen2.png)

Now that the proxy can view and modify the cleartext request we can simply forward out version of it out to the remote server and get a response back!


So far this project has taught me quite a lot and has made me appreciate the work that has gone into creating the protocols and tools I use every day, and I'm sure there's plenty more I can learn from it. There's much to be done still from optimizations and bug fixing to adding more features to play around with requests. I hope you found this devlog to be informative/helpful! I plan to write part 2 of this in the near future so stay tuned! 




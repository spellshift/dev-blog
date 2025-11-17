---
layout: post
title: Redirectors - he's here he's there he's every where
subtitle: Bouncing connections!
gh-repo: spellshift/realm
gh-badge: [star, fork, follow]
tags: [tavern, infra]
comments: true
mathjax: true
author: Hulto
---

## The need for redirectors

Why do we even need a redirector?

Redirectors provide three main benefits in command and control infrastructure. 


First, they obfuscate the true location of the C2 server by acting as an intermediary layer that masks the actual backend infrastructure from defenders and security tools attempting to identify and block malicious activity.


Second, they enable architectural flexibility by allowing a single backend server to operate behind multiple domains, IP addresses, and hosting providers, making it significantly more difficult to completely disrupt the C2 infrastructure through blocking or takedown attempts.


Lastly we want to avoid direct access to a C2 framework to both minimize fingerprinting as well as prevent attacks on the control plane. By introducing redirectors we can now easily place the tavern C2 server in a private VPC behind a VPN or Identity Aware Proxy (IAP) 

## The need for multiple transports

Supporting multiple transport protocols is essential for maintaining operational security and ensuring reliable communication channels.


By implementing diverse transport mechanisms, we can avoid generating easily identifiable network traffic patterns that security tools and analysts could use to detect and classify our C2 communications as malicious.


Additionally, multiple transports provide critical flexibility in restricted network environments where certain protocols may be blocked or heavily monitored, allowing agents to adapt and find alternative communication paths back to the C2 infrastructure.


## Implementation

Normally redirectors are just a reverse proxy using something like nginx or apache, they may even be as simple as a socat redirect. These approaches work in most situtations however because GRPC is still a newer protocol we've run into a number of edge cases when using exsting solutions. None of these issues were blockers but caused us or other users to lose time modifynig configuration. 

In an attempt to solve both the needs above and improve users quality of life we've created a new sub-command in tavern `redirector`.
This allows you to do traditional redirection using the `./tavern redirector --grpc` command to forward grpc connections from the current host to an upstream Tavern server.

But we've also added a redirector per transport allowing developers to have full control over the transport from agent to server. Currently we've only implemented HTTP1 but are looknig forward to adding more.

In order to keep Realm's architecture simple we decided that agents should use Tavern's public key to encrypt traffic instead of each redirector having their own keys. This makes key management simpler but means that the redirector can't unmarshall the encrypted messages. Since GRPC wants all data to be strongly typed (usually a very good thing) this meant we needed a creative solution to copying the raw grpc bytes. This custom codec overrides the Marshall / Unmarshall steps instead returning raw bytes. This allows the redirector to pass the encyrpted protobufs along with no knowledege of the proto spec.

```go
type RawCodec struct{}

func (RawCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}
	return nil, fmt.Errorf("failed to marshal, message is %T", v)
}

func (RawCodec) Unmarshal(data []byte, v any) error {
	if b, ok := v.(*[]byte); ok {
		*b = data
		return nil
	}
	return fmt.Errorf("failed to unmarshal, message is %T", v)
}

func (RawCodec) Name() string {
	return "raw"
}

func init() {
	encoding.RegisterCodec(RawCodec{})
}
```

Keping communication encrypted even at the redirector layer not only simplifies key management but also that redirectors can be run in untrusted locations.

Another unusual issue we encountered when writing the redirector's upstream connection is that grpc prefers ipv6 but many networks (my home network included) don't support IPv6. The GRPC client will use only ipv6 if a AAAA record is present and GCP Cloud Run provisions AAAA records for workloads. To get around this we added a custom dialer to the client that manually resolves, and connects to the upstream tavern server.

```go
	conn, err := grpc.NewClient(
		url.Host,
		grpc.WithTransportCredentials(tc),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			// Resolve using IPv4 only (A records, not AAAA records)
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", url.Hostname())
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IPv4 addresses found for %s", url.Hostname())
			}

			// Force IPv4 by using "tcp4" instead of "tcp"
			dialer := &net.Dialer{}
			tcpConn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), port))
			if err != nil {
				return nil, err
			}

			return tcpConn, nil
		}),
	)
```

This forces IPv4, if we encounter a situation where only IPv6 is available we'll need to revist this and add some form of failover but for now it's working.


## Best Practices

When deploying redirector infrastructure, there are several best practices to follow for improved operational security.

First, always deploy multiple redirectors rather than relying on a single point of failure. This redundancy ensures that if one redirector is detected and blocked, the remaining agents will be able to callback through your the remaining redirectors, maintaining persistent access to your deployed agents.

Second, ensure that each redirector uses a unique IP address, DNS domain, and hosting provider. This diversity makes it significantly more difficult for defenders to perform infrastructure correlation and takedown operations, as blocking or seizing one redirector provides minimal intelligence about the others and doesn't impact overall operations.

Finally, deploy your Tavern C2 server in a non-default VPC with strict network access controls that block all inbound connections except those originating from your authorized redirectors. This network segmentation provides defense in depth, ensuring that even if your redirector locations are discovered, attackers cannot directly access or attack the core C2 infrastructure without first compromising a redirector.



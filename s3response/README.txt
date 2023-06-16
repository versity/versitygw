https://doc.s3.amazonaws.com/2006-03-01/AmazonS3.xsd

see https://blog.aqwari.net/xml-schema-go/

go install aqwari.net/xml/cmd/xsdgen@latest
xsdgen -o s3api_xsd_generated.go -pkg s3response AmazonS3.xsd

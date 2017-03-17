package storage

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A Blob is an entry in BlobListResponse.
type Blob struct {
	Container  *Container
	Name       string         `xml:"Name"`
	Properties BlobProperties `xml:"Properties"`
	Metadata   BlobMetadata   `xml:"Metadata"`
}

// PutBlobOptions includes the options any put blob operation
// (page, block, append)
type PutBlobOptions struct {
	Timeout           uint
	LeaseID           string     `header:"x-ms-lease-id"`
	Origin            string     `header:"Origin"`
	IfModifiedSince   *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince *time.Time `header:"If-Unmodified-Since"`
	IfMatch           string     `header:"If-Match"`
	IfNoneMatch       string     `header:"If-None-Match"`
	RequestID         string     `header:"x-ms-client-request-id"`
}

// BlobMetadata is a set of custom name/value pairs.
//
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Setting-and-Retrieving-Properties-and-Metadata-for-Blob-Resources
type BlobMetadata map[string]string

type blobMetadataEntries struct {
	Entries []blobMetadataEntry `xml:",any"`
}
type blobMetadataEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// UnmarshalXML converts the xml:Metadata into Metadata map
func (bm *BlobMetadata) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var entries blobMetadataEntries
	if err := d.DecodeElement(&entries, &start); err != nil {
		return err
	}
	for _, entry := range entries.Entries {
		if *bm == nil {
			*bm = make(BlobMetadata)
		}
		(*bm)[strings.ToLower(entry.XMLName.Local)] = entry.Value
	}
	return nil
}

// MarshalXML implements the xml.Marshaler interface. It encodes
// metadata name/value pairs as they would appear in an Azure
// ListBlobs response.
func (bm BlobMetadata) MarshalXML(enc *xml.Encoder, start xml.StartElement) error {
	entries := make([]blobMetadataEntry, 0, len(bm))
	for k, v := range bm {
		entries = append(entries, blobMetadataEntry{
			XMLName: xml.Name{Local: http.CanonicalHeaderKey(k)},
			Value:   v,
		})
	}
	return enc.EncodeElement(blobMetadataEntries{
		Entries: entries,
	}, start)
}

// BlobProperties contains various properties of a blob
// returned in various endpoints like ListBlobs or GetBlobProperties.
type BlobProperties struct {
	LastModified            TimeRFC1123 `xml:"Last-Modified"`
	Etag                    string      `xml:"Etag"`
	ContentMD5              string      `xml:"Content-MD5" header:"x-ms-blob-content-md5"`
	ContentLength           int64       `xml:"Content-Length"`
	ContentType             string      `xml:"Content-Type" header:"x-ms-blob-content-type"`
	ContentEncoding         string      `xml:"Content-Encoding" header:"x-ms-blob-content-encoding"`
	CacheControl            string      `xml:"Cache-Control" header:"x-ms-blob-cache-control"`
	ContentLanguage         string      `xml:"Cache-Language" header:"x-ms-blob-content-language"`
	ContentDisposition      string      `xml:"Content-Disposition" header:"x-ms-blob-content-disposition"`
	BlobType                BlobType    `xml:"x-ms-blob-blob-type"`
	SequenceNumber          int64       `xml:"x-ms-blob-sequence-number"`
	CommittedBlockCount     int64
	CopyID                  string      `xml:"CopyId"`
	CopyStatus              string      `xml:"CopyStatus"`
	CopySource              string      `xml:"CopySource"`
	CopyProgress            string      `xml:"CopyProgress"`
	CopyCompletionTime      TimeRFC1123 `xml:"CopyCompletionTime"`
	CopyStatusDescription   string      `xml:"CopyStatusDescription"`
	LeaseStatus             string      `xml:"LeaseStatus"`
	LeaseState              string      `xml:"LeaseState"`
	LeaseDuration           string      `xml:"LeaseDuration"`
	ServerEncrypted         bool        `xml:"ServerEncrypted"`
	IncrementalCopy         bool        `xml:"IncrementalCopy"`
	CopyDestinationSnapshot TimeRFC1123
}

// BlobType defines the type of the Azure Blob.
type BlobType string

// Types of page blobs
const (
	BlobTypeBlock  BlobType = "BlockBlob"
	BlobTypePage   BlobType = "PageBlob"
	BlobTypeAppend BlobType = "AppendBlob"
)

func (b *Blob) buildPath() string {
	return b.Container.buildPath() + "/" + b.Name
}

// Exists returns true if a blob with given name exists on the specified
// container of the storage account.
func (b *Blob) Exists() (bool, error) {
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), nil)
	headers := b.Container.bsc.client.getStandardHeaders()
	resp, err := b.Container.bsc.client.exec(http.MethodHead, uri, headers, nil, b.Container.bsc.auth)
	if resp != nil {
		defer readAndCloseBody(resp.body)
		if resp.statusCode == http.StatusOK || resp.statusCode == http.StatusNotFound {
			return resp.statusCode == http.StatusOK, nil
		}
	}
	return false, err
}

// GetURL gets the canonical URL to the blob with the specified name in the
// specified container. If name is not specified, the canonical URL for the entire
// container is obtained.
// This method does not create a publicly accessible URL if the blob or container
// is private and this method does not check if the blob exists.
func (b *Blob) GetURL() string {
	container := b.Container.Name
	if container == "" {
		container = "$root"
	}
	return b.Container.bsc.client.getEndpoint(blobServiceName, pathForResource(container, b.Name), nil)
}

// GetBlobRangeOptions includes the options for a get blob range operation
type GetBlobRangeOptions struct {
	Range              *BlobRange
	GetRangeContentMD5 bool
	*GetBlobOptions
}

// GetBlobOptions includes the options for a get blob operation
type GetBlobOptions struct {
	Timeout           uint
	Snapshot          *time.Time
	LeaseID           string     `header:"x-ms-lease-id"`
	Origin            string     `header:"Origin"`
	IfModifiedSince   *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince *time.Time `header:"If-Unmodified-Since"`
	IfMatch           string     `header:"If-Match"`
	IfNoneMatch       string     `header:"If-None-Match"`
	RequestID         string     `header:"x-ms-client-request-id"`
}

// BlobRange represents the bytes range to be get
type BlobRange struct {
	Start uint64
	End   uint64
}

func (br BlobRange) String() string {
	return fmt.Sprintf("bytes=%d-%d", br.Start, br.End)
}

// GetBlobResponse includes data result of a get blob operation
type GetBlobResponse struct {
	Body io.ReadCloser
	ResponseInfo
	*OriginResponse
}

// Get returns a stream to read the blob. Caller must call both Read and Close()
// to correctly close the underlying connection.
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Get-Blob
func (b *Blob) Get(options *GetBlobOptions) (GetBlobResponse, error) {
	rangeOptions := GetBlobRangeOptions{
		GetBlobOptions: options,
	}
	resp, respErr := b.getRange(&rangeOptions)
	if respErr != nil {
		gbr, err := getBlobResponder(resp, options, []int{http.StatusOK})
		if err != nil {
			return gbr, addOtherErrors(respErr, err)
		}
		return gbr, err
	}

	gbr, err := getBlobResponder(resp, options, []int{http.StatusOK})
	if err != nil {
		return gbr, err
	}

	// Get Blob operation does not include headers for IncrementalCopy nor for CopyDestinationSnapshot
	// This prevents overwriting them with incorrect values
	ic, cds := b.Properties.IncrementalCopy, b.Properties.CopyDestinationSnapshot
	err = b.propertiesFromHeaders(resp.headers)
	b.Properties.IncrementalCopy, b.Properties.CopyDestinationSnapshot = ic, cds
	gbr.Body = resp.body

	return gbr, err
}

func getBlobResponder(resp *storageResponse, options *GetBlobOptions, status []int) (GetBlobResponse, error) {
	var gbr GetBlobResponse
	ri, err := responder(resp, status)
	gbr.ResponseInfo = ri
	if err != nil {
		return gbr, err
	}

	if options != nil && options.Origin != "" {
		or, err := getOriginResponse(resp.headers)
		if err != nil {
			return gbr, err
		}
		gbr.OriginResponse = or
	}

	return gbr, nil
}

// GetBlobRangeResponse includes data result of a get blob range operation
type GetBlobRangeResponse struct {
	GetBlobResponse
	ContentMD5 string
}

// GetRange reads the specified range of a blob to a stream. The bytesRange
// string must be in a format like "0-", "10-100" as defined in HTTP 1.1 spec.
// Caller must call both Read and Close()// to correctly close the underlying
// connection.
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Get-Blob
func (b *Blob) GetRange(options *GetBlobRangeOptions) (gbrr GetBlobRangeResponse, err error) {
	resp, err := b.getRange(options)
	if err != nil {
		gbr, respErr := getBlobResponder(resp, options.GetBlobOptions, []int{http.StatusPartialContent})
		gbrr.GetBlobResponse = gbr
		if err != nil {
			return gbrr, addOtherErrors(respErr, err)
		}
		return gbrr, err
	}

	gbr, err := getBlobResponder(resp, options.GetBlobOptions, []int{http.StatusPartialContent})
	gbrr.GetBlobResponse = gbr
	if err != nil {
		return gbrr, err
	}

	// Get Blob operation does not include headers for IncrementalCopy nor for CopyDestinationSnapshot
	// Lets prevent overwriting them with incorrecvt values
	ic, cds := b.Properties.IncrementalCopy, b.Properties.CopyDestinationSnapshot
	err = b.propertiesFromHeaders(resp.headers)
	b.Properties.IncrementalCopy, b.Properties.CopyDestinationSnapshot = ic, cds

	gbrr.Body = resp.body
	gbrr.ContentMD5 = resp.headers.Get("Content-MD5")

	return gbrr, nil
}

func (b *Blob) getRange(options *GetBlobRangeOptions) (*storageResponse, error) {
	params := url.Values{}
	headers := b.Container.bsc.client.getStandardHeaders()

	if options != nil {
		if options.Range != nil {
			headers["Range"] = options.Range.String()
			headers["x-ms-range-get-content-md5"] = fmt.Sprintf("%v", options.GetRangeContentMD5)
		}
		if options.GetBlobOptions != nil {
			headers = mergeHeaders(headers, headersFromStruct(*options.GetBlobOptions))
			params = addTimeout(params, options.Timeout)
			params = addSnapshot(params, options.Snapshot)
		}
	}
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), params)

	return b.Container.bsc.client.exec(http.MethodGet, uri, headers, nil, b.Container.bsc.auth)
}

// SnapshotOptions includes the options for a snapshot blob operation
type SnapshotOptions struct {
	Timeout           uint
	LeaseID           string     `header:"x-ms-lease-id"`
	IfModifiedSince   *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince *time.Time `header:"If-Unmodified-Since"`
	IfMatch           string     `header:"If-Match"`
	IfNoneMatch       string     `header:"If-None-Match"`
	RequestID         string     `header:"x-ms-client-request-id"`
}

// SnapshotResponse includes data result of a snapshot blob operation
type SnapshotResponse struct {
	ResponseInfo
	Snapshot time.Time
}

// Snapshot creates a snapshot for a blob
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Snapshot-Blob
func (b *Blob) Snapshot(options *SnapshotOptions) (SnapshotResponse, error) {
	params := url.Values{"comp": {"snapshot"}}
	headers := b.Container.bsc.client.getStandardHeaders()
	headers = b.Container.bsc.client.addMetadataToHeaders(headers, b.Metadata)

	if options != nil {
		params = addTimeout(params, options.Timeout)
		headers = mergeHeaders(headers, headersFromStruct(*options))
	}
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), params)

	resp, respErr := b.Container.bsc.client.exec(http.MethodPut, uri, headers, nil, b.Container.bsc.auth)
	if respErr != nil {
		ri, err := responder(resp, []int{http.StatusCreated})
		sr := SnapshotResponse{
			ResponseInfo: ri,
		}
		if err != nil {
			return sr, addOtherErrors(respErr, err)
		}
		return sr, err
	}
	defer readAndCloseBody(resp.body)

	ri, err := responder(resp, []int{http.StatusCreated})
	sr := SnapshotResponse{
		ResponseInfo: ri,
	}
	if err != nil {
		return sr, err
	}

	err = b.updateEtagAndLastModified(resp.headers)
	if err != nil {
		return sr, err
	}

	snap, err := getTimeFromHeaders(resp.headers, "x-ms-snapshot")
	if err != nil {
		return sr, err
	}
	sr.Snapshot = snap

	return sr, nil
}

// GetBlobPropertiesOptions includes the options for a get blob properties operation
type GetBlobPropertiesOptions struct {
	Timeout           uint
	Snapshot          *time.Time
	LeaseID           string     `header:"x-ms-lease-id"`
	IfModifiedSince   *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince *time.Time `header:"If-Unmodified-Since"`
	IfMatch           string     `header:"If-Match"`
	IfNoneMatch       string     `header:"If-None-Match"`
	RequestID         string     `header:"x-ms-client-request-id"`
}

// GetBlobPropertiesResponse includes data result of a get blob properties operation
type GetBlobPropertiesResponse struct {
	ResponseInfo
	AcceptRange string
}

// GetProperties provides various information about the specified blob.
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Get-Blob-Properties
func (b *Blob) GetProperties(options *GetBlobPropertiesOptions) (GetBlobPropertiesResponse, error) {
	params := url.Values{}
	headers := b.Container.bsc.client.getStandardHeaders()

	if options != nil {
		params = addTimeout(params, options.Timeout)
		params = addSnapshot(params, options.Snapshot)
		headers = mergeHeaders(headers, headersFromStruct(*options))
	}
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), params)

	resp, respErr := b.Container.bsc.client.exec(http.MethodHead, uri, headers, nil, b.Container.bsc.auth)
	if respErr != nil {
		ri, err := responder(resp, []int{http.StatusOK})
		gbpr := GetBlobPropertiesResponse{
			ResponseInfo: ri,
		}
		if err != nil {
			return gbpr, addOtherErrors(respErr, err)
		}
	}
	defer readAndCloseBody(resp.body)

	ri, err := responder(resp, []int{http.StatusOK})
	gbpr := GetBlobPropertiesResponse{
		ResponseInfo: ri,
	}
	if err != nil {
		return gbpr, err
	}

	err = b.propertiesFromHeaders(resp.headers)
	if err != nil {
		return gbpr, err
	}
	gbpr.AcceptRange = resp.headers.Get("Accept-Ranges")

	return gbpr, nil
}

// SetBlobPropertiesOptions contains various properties of a blob and is an entry
// in SetProperties
type SetBlobPropertiesOptions struct {
	Timeout              uint
	LeaseID              string     `header:"x-ms-lease-id"`
	Origin               string     `header:"Origin"`
	IfModifiedSince      *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince    *time.Time `header:"If-Unmodified-Since"`
	IfMatch              string     `header:"If-Match"`
	IfNoneMatch          string     `header:"If-None-Match"`
	SequenceNumberAction *SequenceNumberAction
	RequestID            string `header:"x-ms-client-request-id"`
}

// SequenceNumberAction defines how the blob's sequence number should be modified
type SequenceNumberAction string

// Options for sequence number action
const (
	SequenceNumberActionMax       SequenceNumberAction = "max"
	SequenceNumberActionUpdate    SequenceNumberAction = "update"
	SequenceNumberActionIncrement SequenceNumberAction = "increment"
)

// SetBlobPropertiesResponse includes data result of a set blob properties operation
type SetBlobPropertiesResponse struct {
	ResponseInfo
	*OriginResponse
}

// SetProperties replaces the BlobHeaders for the specified blob.
//
// Some keys may be converted to Camel-Case before sending. All keys
// are returned in lower case by GetBlobProperties. HTTP header names
// are case-insensitive so case munging should not matter to other
// applications either.
//
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Set-Blob-Properties
func (b *Blob) SetProperties(options *SetBlobPropertiesOptions) (SetBlobPropertiesResponse, error) {
	params := url.Values{"comp": {"properties"}}
	headers := b.Container.bsc.client.getStandardHeaders()
	headers = mergeHeaders(headers, headersFromStruct(b.Properties))

	if options != nil {
		params = addTimeout(params, options.Timeout)
		headers = mergeHeaders(headers, headersFromStruct(*options))
	}
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), params)

	if b.Properties.BlobType == BlobTypePage {
		headers = addToHeaders(headers, "x-ms-blob-content-length", fmt.Sprintf("byte %v", b.Properties.ContentLength))
		if options != nil || options.SequenceNumberAction != nil {
			headers = addToHeaders(headers, "x-ms-sequence-number-action", string(*options.SequenceNumberAction))
			if *options.SequenceNumberAction != SequenceNumberActionIncrement {
				headers = addToHeaders(headers, "x-ms-blob-sequence-number", fmt.Sprintf("%v", b.Properties.SequenceNumber))
			}
		}
	}

	resp, respErr := b.Container.bsc.client.exec(http.MethodPut, uri, headers, nil, b.Container.bsc.auth)
	if respErr != nil {
		sbpr, err := setBlobPropertiesResponder(resp, options, []int{http.StatusOK})
		if err != nil {
			return sbpr, addOtherErrors(respErr, err)
		}
	}
	defer readAndCloseBody(resp.body)

	sbpr, err := setBlobPropertiesResponder(resp, options, []int{http.StatusOK})
	if err != nil {
		return sbpr, err
	}

	if err = b.updateEtagAndLastModified(resp.headers); err != nil {
		return sbpr, err
	}

	return sbpr, nil
}

func setBlobPropertiesResponder(resp *storageResponse, options *SetBlobPropertiesOptions, status []int) (SetBlobPropertiesResponse, error) {
	var sbpr SetBlobPropertiesResponse
	ri, err := responder(resp, status)
	sbpr.ResponseInfo = ri
	if err != nil {
		return sbpr, err
	}

	if options != nil && options.Origin != "" {
		or, err := getOriginResponse(resp.headers)
		if err != nil {
			return sbpr, err
		}
		sbpr.OriginResponse = or
	}

	return sbpr, nil
}

// SetBlobMetadataOptions includes the options for a set blob metadata operation
type SetBlobMetadataOptions struct {
	Timeout           uint
	LeaseID           string     `header:"x-ms-lease-id"`
	IfModifiedSince   *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince *time.Time `header:"If-Unmodified-Since"`
	IfMatch           string     `header:"If-Match"`
	IfNoneMatch       string     `header:"If-None-Match"`
	RequestID         string     `header:"x-ms-client-request-id"`
}

// SetBlobMetadataResponse includes data result of a set blob metadata operation
type SetBlobMetadataResponse struct {
	ResponseInfo
	RequestServerEncypted bool
}

// SetMetadata replaces the metadata for the specified blob.
//
// Some keys may be converted to Camel-Case before sending. All keys
// are returned in lower case by GetBlobMetadata. HTTP header names
// are case-insensitive so case munging should not matter to other
// applications either.
//
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Set-Blob-Metadata
func (b *Blob) SetMetadata(options *SetBlobMetadataOptions) (SetBlobMetadataResponse, error) {
	params := url.Values{"comp": {"metadata"}}
	headers := b.Container.bsc.client.getStandardHeaders()
	headers = b.Container.bsc.client.addMetadataToHeaders(headers, b.Metadata)

	if options != nil {
		params = addTimeout(params, options.Timeout)
		headers = mergeHeaders(headers, headersFromStruct(*options))
	}
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), params)

	resp, respErr := b.Container.bsc.client.exec(http.MethodPut, uri, headers, nil, b.Container.bsc.auth)
	if respErr != nil {
		ri, err := responder(resp, []int{http.StatusOK})
		sbmr := SetBlobMetadataResponse{
			ResponseInfo: ri,
		}
		if err != nil {
			return sbmr, addOtherErrors(respErr, err)
		}
	}
	defer readAndCloseBody(resp.body)

	ri, err := responder(resp, []int{http.StatusOK})
	sbmr := SetBlobMetadataResponse{
		ResponseInfo: ri,
	}
	if err != nil {
		return sbmr, err
	}

	encryptedRequest, err := getBoolFromHeaders(resp.headers, "x-ms-request-server-encrypted")
	if err != nil {
		return sbmr, err
	}
	sbmr.RequestServerEncypted = encryptedRequest

	return sbmr, nil
}

// GetBlobMetadataOptions includes the options for a get blob metadata operation
type GetBlobMetadataOptions struct {
	Timeout           uint
	Snapshot          *time.Time
	LeaseID           string     `header:"x-ms-lease-id"`
	IfModifiedSince   *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince *time.Time `header:"If-Unmodified-Since"`
	IfMatch           string     `header:"If-Match"`
	IfNoneMatch       string     `header:"If-None-Match"`
	RequestID         string     `header:"x-ms-client-request-id"`
}

// GetMetadata returns all user-defined metadata for the specified blob.
//
// All metadata keys will be returned in lower case. (HTTP header
// names are case-insensitive.)
//
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/get-blob-metadata
func (b *Blob) GetMetadata(options *GetBlobMetadataOptions) (ResponseInfo, error) {
	params := url.Values{"comp": {"metadata"}}
	headers := b.Container.bsc.client.getStandardHeaders()

	if options != nil {
		params = addTimeout(params, options.Timeout)
		params = addSnapshot(params, options.Snapshot)
		headers = mergeHeaders(headers, headersFromStruct(*options))
	}
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), params)

	resp, respErr := b.Container.bsc.client.exec(http.MethodGet, uri, headers, nil, b.Container.bsc.auth)
	if respErr != nil {
		ri, err := responder(resp, []int{http.StatusOK})
		if err != nil {
			return ri, addOtherErrors(respErr, err)
		}
	}
	defer readAndCloseBody(resp.body)

	ri, err := responder(resp, []int{http.StatusOK})
	if err != nil {
		return ri, err
	}

	metadata := getMetadataFromHeaders(resp.headers)
	b.Metadata = BlobMetadata(metadata)

	err = b.updateEtagAndLastModified(resp.headers)
	if err != nil {
		return ri, err
	}

	return ri, nil
}

// DeleteBlobOptions includes the options for a delete blob operation
type DeleteBlobOptions struct {
	Timeout           uint
	Snapshot          *time.Time
	LeaseID           string `header:"x-ms-lease-id"`
	DeleteSnapshots   *bool
	IfModifiedSince   *time.Time `header:"If-Modified-Since"`
	IfUnmodifiedSince *time.Time `header:"If-Unmodified-Since"`
	IfMatch           string     `header:"If-Match"`
	IfNoneMatch       string     `header:"If-None-Match"`
	RequestID         string     `header:"x-ms-client-request-id"`
}

// Delete deletes the given blob from the specified container.
// If the blob does not exists at the time of the Delete Blob operation, it
// returns error.
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Delete-Blob
func (b *Blob) Delete(options *DeleteBlobOptions) (ResponseInfo, error) {
	resp, respErr := b.delete(options)
	if respErr != nil {
		ri, err := responder(resp, []int{http.StatusAccepted})
		if err != nil {
			return ri, addOtherErrors(respErr, err)
		}
	}
	defer readAndCloseBody(resp.body)

	ri, err := responder(resp, []int{http.StatusAccepted})
	if err != nil {
		return ri, err
	}

	return ri, err
}

// DeleteIfExists deletes the given blob from the specified container If the
// blob is deleted with this call, returns true. Otherwise returns false.
//
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Delete-Blob
func (b *Blob) DeleteIfExists(options *DeleteBlobOptions) (bool, ResponseInfo, error) {
	resp, respErr := b.delete(options)
	if respErr != nil {
		ri, err := responder(resp, []int{http.StatusAccepted, http.StatusNotFound})
		if err != nil {
			return false, ri, addOtherErrors(respErr, err)
		}
		if resp.statusCode == http.StatusAccepted || resp.statusCode == http.StatusNotFound {
			return resp.statusCode == http.StatusAccepted, ri, nil
		}
	}
	ri, err := responder(resp, []int{http.StatusAccepted})
	return false, ri, err
}

func (b *Blob) delete(options *DeleteBlobOptions) (*storageResponse, error) {
	params := url.Values{}
	headers := b.Container.bsc.client.getStandardHeaders()

	if options != nil {
		params = addTimeout(params, options.Timeout)
		params = addSnapshot(params, options.Snapshot)
		headers = mergeHeaders(headers, headersFromStruct(*options))
		if options.DeleteSnapshots != nil {
			if *options.DeleteSnapshots {
				headers["x-ms-delete-snapshots"] = "include"
			} else {
				headers["x-ms-delete-snapshots"] = "only"
			}
		}
	}
	uri := b.Container.bsc.client.getEndpoint(blobServiceName, b.buildPath(), params)
	return b.Container.bsc.client.exec(http.MethodDelete, uri, headers, nil, b.Container.bsc.auth)
}

// helper method to construct the path to either a blob or container
func pathForResource(container, name string) string {
	if name != "" {
		return fmt.Sprintf("/%s/%s", container, name)
	}
	return fmt.Sprintf("/%s", container)
}

func (b *Blob) propertiesFromHeaders(h http.Header) error {
	contentLength, err := getInt64FromHeaders(h, "Content-Length")
	if err != nil {
		return err
	}
	sequenceNum, err := getInt64FromHeaders(h, "x-ms-blob-sequence-number")
	if err != nil {
		return err
	}
	committedBlobkCount, err := getInt64FromHeaders(h, "x-ms-blob-committed-block-count")
	if err != nil {
		return err
	}
	lastModified, err := getTimeFromHeaders(h, "Last-Modified")
	if err != nil {
		return err
	}
	copyCompletionTime, err := getTimeFromHeaders(h, "x-ms-copy-completion-time")
	if err != nil {
		return err
	}
	serverEncrypted, err := getBoolFromHeaders(h, "x-ms-server-encrypted")
	if err != nil {
		return err
	}
	incrementalCopy, err := getBoolFromHeaders(h, "x-ms-incremental-copy")
	if err != nil {
		return err
	}
	copyDestinationSnapshot, err := getTimeFromHeaders(h, "x-ms-copy-destination-snapshot")
	if err != nil {
		return err
	}

	b.Properties = BlobProperties{
		LastModified:            TimeRFC1123(lastModified),
		Etag:                    h.Get("Etag"),
		ContentMD5:              h.Get("Content-MD5"),
		ContentLength:           contentLength,
		ContentType:             h.Get("Content-Type"),
		ContentEncoding:         h.Get("Content-Encoding"),
		CacheControl:            h.Get("Cache-Control"),
		ContentLanguage:         h.Get("Content-Language"),
		ContentDisposition:      h.Get("Content-Disposition"),
		BlobType:                BlobType(h.Get("x-ms-blob-type")),
		SequenceNumber:          sequenceNum,
		CommittedBlockCount:     committedBlobkCount,
		CopyID:                  h.Get("x-ms-copy-id"),
		CopyStatus:              h.Get("x-ms-copy-status"),
		CopySource:              h.Get("x-ms-copy-source"),
		CopyProgress:            h.Get("x-ms-copy-progress"),
		CopyCompletionTime:      TimeRFC1123(copyCompletionTime),
		CopyStatusDescription:   h.Get("x-ms-copy-status-description"),
		LeaseStatus:             h.Get("x-ms-lease-status"),
		LeaseState:              h.Get("x-ms-lease-state"),
		LeaseDuration:           h.Get("x-ms-lease-duration"),
		ServerEncrypted:         serverEncrypted,
		IncrementalCopy:         incrementalCopy,
		CopyDestinationSnapshot: TimeRFC1123(copyDestinationSnapshot),
	}
	metadata := getMetadataFromHeaders(h)
	b.Metadata = BlobMetadata(metadata)
	return nil
}

// updates Etag and last modified date
func (b *Blob) updateEtagAndLastModified(headers http.Header) error {
	lm, err := getTimeFromHeaders(headers, "Last-Modified")
	if err != nil {
		return err
	}
	b.Properties.LastModified = TimeRFC1123(lm)
	b.Properties.Etag = headers.Get("Etag")
	return nil
}

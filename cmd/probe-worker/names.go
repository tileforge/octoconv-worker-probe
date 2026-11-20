package main

import "errors"

var errAssignmentInputs = errors.New("assignment inputs")

type extraFile struct {
	name string
	body []byte
}

type namedInput struct {
	link fileLinkJSON
	name string
}

// classifyInputs accepts one source at ordinal 0. A second part is not a sanitize input.
func classifyInputs(links []fileLinkJSON) (fileLinkJSON, []namedInput, error) {
	if len(links) != 1 {
		return fileLinkJSON{}, nil, errAssignmentInputs
	}
	link := links[0]
	if link.Role != "source" || link.Ordinal != 0 || link.Href == "" || link.Format == "" {
		return fileLinkJSON{}, nil, errAssignmentInputs
	}
	if _, err := requireHTTPS(link.Href); err != nil {
		return fileLinkJSON{}, nil, err
	}
	return link, nil, nil
}

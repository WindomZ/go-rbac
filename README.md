# go-rbac
[![Build Status](https://travis-ci.org/WindomZ/go-rbac.svg?branch=master)](https://travis-ci.org/WindomZ/go-rbac)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A simplified role-based access control (RBAC) implementation, 
inspired by [gorbac](https://github.com/mikespook/gorbac)

![v0.5.0](https://img.shields.io/badge/version-v0.5.0-yellow.svg)
![status](https://img.shields.io/badge/status-beta-yellow.svg)

The exported functions could *change* at any time before the first *stable release*(>=1.0.0).

## Purpose

* Only three objects: `identity`, `role` and `permission`
* One to many relationship between `identity` and `roles`.
* One to many relationship between `role` and `permissions`.
* One to many relationship between `role` and parent `roles`(inheritance relationship).

## Features

- [x] An `identity` has one or more `roles`.
- [x] A `role` has one or more `permissions`.
- [x] A `role` can inherit one or more other `roles`(inheriting their `permissions`).
- [x] Both `identity`, `role`, `permission` are defined by ID string.
- [x] Pure no third party library dependent.

## Installation

```
go get -u github.com/WindomZ/go-rbac
```

## License

The [MIT License](https://github.com/WindomZ/go-rbac/blob/master/LICENSE)

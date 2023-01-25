package paginatesc

import (
	"strconv"

	"gorm.io/gorm"
)

type PaginateModel struct {
	Page int

	PerPage int
}

func Paginate(r *PaginateModel) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {

		p := normalizePaginateModel(*r)

		offset := (p.Page - 1) * p.PerPage

		return db.Offset(offset).Limit(p.PerPage)
	}
}

func (param *PaginateModel) CreatePaginateModel(pageRaw string, perPageRaw string) PaginateModel {
	p := PaginateModel{}

	page, err := strconv.Atoi(pageRaw)
	if err != nil {
		p.Page = 1
	} else {
		p.Page = page
	}

	pageSize, err := strconv.Atoi(perPageRaw)

	if err != nil {
		p.PerPage = 10
	} else {
		p.PerPage = pageSize
	}

	p = normalizePaginateModel(p)

	return p
}

func normalizePaginateModel(p PaginateModel) PaginateModel {
	if p.Page == 0 {
		p.Page = 1
	}

	switch {
	case p.PerPage > 100:
		p.PerPage = 100
	case p.PerPage <= 0:
		p.PerPage = 10
	}

	return p
}

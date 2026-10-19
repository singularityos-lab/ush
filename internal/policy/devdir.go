package policy

const (
	CategoryDevDir    Category = "devdir"
	CategoryDevDirDev Category = "devdir-dev"
)

func DevDirCategories(dev bool) []Category {
	if dev {
		return []Category{CategoryDevDir, CategoryDevDirDev}
	}
	return []Category{CategoryDevDir}
}

func IsDevDirCategory(c Category, dev bool) bool {
	for _, d := range DevDirCategories(dev) {
		if c == d {
			return true
		}
	}
	return false
}

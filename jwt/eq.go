package jwt

import "reflect"

// eq returns true if the two types are either strings
// or comparable slices.
func eq(a, b interface{}) bool {
	t1 := reflect.TypeOf(a)
	t2 := reflect.TypeOf(b)

	if t1.Kind() == t2.Kind() {
		switch t1.Kind() {
		case reflect.Slice:
			return eqSlice(a, b)
		case reflect.String:
			return reflect.ValueOf(a).String() ==
				reflect.ValueOf(b).String()
		}
	}
	return false
}

// eqSlice returns true if the two interfaces are both slices
// and are equal. For example: https://play.golang.org/p/5VLMwNE3i-
func eqSlice(a, b interface{}) bool {
	if a == nil || b == nil {
		return false
	}

	v1 := reflect.ValueOf(a)
	v2 := reflect.ValueOf(b)

	if v1.Kind() != reflect.Slice ||
		v2.Kind() != reflect.Slice {
		return false
	}

	if v1.Len() == v2.Len() && v1.Len() > 0 {
		for i := 0; i < v1.Len() && i < v2.Len(); i++ {
			k1 := v1.Index(i)
			k2 := v2.Index(i)
			if k1.Type().Comparable() &&
				k2.Type().Comparable() &&
				k1.CanInterface() && k2.CanInterface() &&
				k1.Interface() != k2.Interface() {
				return false
			}
		}
		return true
	}
	return false
}

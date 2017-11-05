package scan

import (
	"io/ioutil"
	"path"
	"reflect"
	"testing"
)

func Test_debian_getFixCVEIDsFromChangelog(t *testing.T) {
	type args struct {
		changelog string
		pack      Package
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "ok",
			args: args{
				pack: Package{
					Name:    "sudo",
					Version: "1.8.10p3-1+deb8u3",
				},
			},
			want: []string{
				"CVE-2015-5602",
				"CVE-2014-9680",
				"CVE-2012-0809",
				"CVE-2010-2956",
				"CVE-2010-1646",
				"CVE-2010-1163",
				"CVE-2010-0426",
				"CVE-2009-0034",
				"CVE-2005-4158",
			},
		},
		{
			name: "diff",
			args: args{
				pack: Package{
					Name:    "sudo",
					Version: "1.8.10p3-1+deb8u2",
				},
			},
			want: []string{
				"CVE-2014-9680",
				"CVE-2012-0809",
				"CVE-2010-2956",
				"CVE-2010-1646",
				"CVE-2010-1163",
				"CVE-2010-0426",
				"CVE-2009-0034",
				"CVE-2005-4158",
			},
		},
		{
			name: "unmatch",
			args: args{
				pack: Package{
					Name:    "sudo",
					Version: "unmatch",
				},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		raw, err := ioutil.ReadFile(path.Join("..", "test", "deb_changelog"))
		if err != nil {
			panic(err)
		}
		tt.args.changelog = string(raw)

		t.Run(tt.name, func(t *testing.T) {
			o := &debian{}
			if got := getCVEIDsFromBody(o.ChangeLogStartPattern(tt.args.pack), tt.args.changelog); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("debian.getFixCVEIDsFromChangelog() = %v, want %v", got, tt.want)
			}
		})
	}
}

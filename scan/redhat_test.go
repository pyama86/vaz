package scan

import (
	"io/ioutil"
	"path"
	"reflect"
	"testing"
)

func Test_redhat_getFixCVEIDsFromChangelog(t *testing.T) {
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
					Name:    "openssl",
					Version: "1.0.1e-60",
				},
			},
			want: []string{
				"CVE-2016-2177",
				"CVE-2016-2178",
				"CVE-2016-2179",
				"CVE-2016-2180",
				"CVE-2016-2181",
				"CVE-2016-2182",
				"CVE-2016-6302",
				"CVE-2016-6304",
				"CVE-2016-6306",
				"CVE-2016-2183",
				"CVE-2016-2105",
				"CVE-2016-2106",
				"CVE-2016-2107",
				"CVE-2016-2108",
				"CVE-2016-2109",
			},
		},
		{
			name: "diff",
			args: args{
				pack: Package{
					Name:    "openssl",
					Version: "1.0.1e-58",
				},
			},
			want: []string{
				"CVE-2016-2105",
				"CVE-2016-2106",
				"CVE-2016-2107",
				"CVE-2016-2108",
				"CVE-2016-2109",
			},
		},
		{
			name: "unmatch",
			args: args{
				pack: Package{
					Name:    "openssl",
					Version: "unmatch",
				},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		raw, err := ioutil.ReadFile(path.Join("..", "test", "rpm_changelog"))
		if err != nil {
			panic(err)
		}
		tt.args.changelog = string(raw)

		t.Run(tt.name, func(t *testing.T) {
			o := &redhat{}
			if got := o.getFixCVEIDsFromChangelog(o.ChangeLogStartPattern(tt.args.pack), tt.args.changelog); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redhat.getFixCVEIDsFromChangelog() = %v, want %v", got, tt.want)
			}
		})
	}
}

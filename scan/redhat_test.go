package scan

import (
	"io/ioutil"
	"path"
	"reflect"
	"testing"
	"time"

	cache "github.com/patrickmn/go-cache"
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
			if got := getCVEIDsFromBody(o.ChangeLogStartPattern(tt.args.pack), tt.args.changelog); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redhat.getFixCVEIDsFromChangelog() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_redhat_getCVEIDsFromSecurityUpdateInfo(t *testing.T) {
	type fields struct {
		ScanResult ScanResult
		cache      *cache.Cache
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				ScanResult: ScanResult{},
				cache:      cache.New(CacheLifeTime*time.Minute, CachePurgeTime*time.Minute),
			},
			args: args{
				name: "openssl",
			},
			want:    []string{"CVE-2016-2179", "CVE-2016-2178", "CVE-2016-6302", "CVE-2016-2181", "CVE-2016-6306", "CVE-2016-2183", "CVE-2016-2182", "CVE-2016-2177", "CVE-2016-2180", "CVE-2017-3731", "CVE-2016-8610"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := getMD5Hash("updateinfo")
			raw, err := ioutil.ReadFile(path.Join("..", "test", "rpm_updateinfo"))
			if err != nil {
				panic(err)
			}
			tt.fields.cache.Set(key, string(raw), cache.DefaultExpiration)

			o := &redhat{
				ScanResult: tt.fields.ScanResult,
				cache:      tt.fields.cache,
			}
			got, err := o.getCVEIDsFromSecurityUpdateInfo(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhat.getCVEIDsFromSecurityUpdateInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redhat.getCVEIDsFromSecurityUpdateInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_redhat_parseSecurityUpdateList(t *testing.T) {
	type fields struct {
		ScanResult ScanResult
		cache      *cache.Cache
	}
	type args struct {
		list string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    Packages
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				ScanResult: ScanResult{},
				cache:      cache.New(CacheLifeTime*time.Minute, CachePurgeTime*time.Minute),
			},
			args: args{
				list: "rpm_updatelist",
			},
			want: Packages{"openvpn": Package{
				Name:    "openvpn",
				Version: "2.4.4",
			}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhat{
				ScanResult: tt.fields.ScanResult,
				cache:      tt.fields.cache,
			}

			raw, err := ioutil.ReadFile(path.Join("..", "test", tt.args.list))
			if err != nil {
				panic(err)
			}

			got, err := o.parseSecurityUpdateList(string(raw))
			if (err != nil) != tt.wantErr {
				t.Errorf("redhat.parseSecurityUpdateList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redhat.parseSecurityUpdateList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_redhat_parseCVEIDsUpdateInfo(t *testing.T) {
	type fields struct {
		ScanResult ScanResult
		cache      *cache.Cache
	}
	type args struct {
		name string
		info string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []string
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhat{
				ScanResult: tt.fields.ScanResult,
				cache:      tt.fields.cache,
			}
			if got := o.parseCVEIDsUpdateInfo(tt.args.name, tt.args.info); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redhat.parseCVEIDsUpdateInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

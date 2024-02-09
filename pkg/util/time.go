package util

import (
	"syscall"
	"time"
)

func KtimeToReal(ktime uint64) (uint64, error) {
	sysinfo := &syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(sysinfo); err != nil {
		return 0, err
	}

	dt := time.Now()
	dt = dt.Add(-1 * (time.Second * time.Duration(uint64(sysinfo.Uptime))))
	return uint64(dt.UnixNano()) + ktime, nil
}

func TimeNow() uint64 {
	return uint64(time.Now().Unix())
}

func TimeNowNano() uint64 {
	return uint64(time.Now().UnixNano())
}

func KtimeToRealNano(ktime uint64) (uint64, error) {
	sysinfo := &syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(sysinfo); err != nil {
		return 0, err
	}

	dt := time.Now()
	dt = dt.Add(-1 * (time.Second * time.Duration(uint64(sysinfo.Uptime))))
	return uint64(dt.UnixNano()) + ktime, nil
}

func KtimeToRealMilli(ktimeMilli uint64) (uint64, error) {
	sysinfo := &syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(sysinfo); err != nil {
		return 0, err
	}

	dt := time.Now()
	dt = dt.Add(-1 * (time.Second * time.Duration(uint64(sysinfo.Uptime))))
	return uint64(dt.UnixMilli()) + ktimeMilli, nil
}

// NOTE(slankdev): It may not work fine...
// THIS_IMPL: 2024-02-09 10:46:39.145877585 +0900 JST
// MY_EXPECT: 2024-02-09 10:51:39.145877585 +0900 JST
// Not sure what's this 5sec...
// presition: nano-second
func KtimeNanoSecToTime(ktimeNsec uint64) (time.Time, error) {
	sysinfo := syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(&sysinfo); err != nil {
		return time.Time{}, err
	}
	unixTimeSecKernelBooted := time.Now().Unix() - sysinfo.Uptime
	unixTimeSecTarget := unixTimeSecKernelBooted
	return time.Unix(unixTimeSecTarget, int64(ktimeNsec)), nil
}

// presition: second
func KtimeSecToTime(ktimeSec uint64) (time.Time, error) {
	sysinfo := syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(&sysinfo); err != nil {
		return time.Time{}, err
	}
	unixTimeSecKernelBooted := time.Now().Unix() - sysinfo.Uptime
	unixTimeSecTarget := unixTimeSecKernelBooted + int64(ktimeSec)
	return time.Unix(unixTimeSecTarget, 0), nil
}

// presition: second
func TimeToKtimeSec(t time.Time) (uint64, error) {
	sysinfo := syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(&sysinfo); err != nil {
		return 0, err
	}
	unixTimeSecKernelBooted := time.Now().Unix() - sysinfo.Uptime
	unixKtimeSecTarget := t.Unix() - unixTimeSecKernelBooted
	return uint64(unixKtimeSecTarget), nil
}

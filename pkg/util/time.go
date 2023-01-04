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

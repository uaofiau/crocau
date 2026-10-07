package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// HostSession - то, что нужно отправителю, чтобы ждать получателя в локальной сети: relay croc на своём компьютере
// (порты TCP) и объявление о себе (UDP), по которому получатель находит отправителя.
type HostSession struct {
	relay   *Job
	stopAnn func()
}

// Close останавливает relay и объявление.
func (h *HostSession) Close() {
	if h == nil {
		return
	}
	if h.stopAnn != nil {
		h.stopAnn()
		h.stopAnn = nil
	}
	if h.relay != nil {
		h.relay.Kill()
		h.relay.Wait(3 * time.Second)
		h.relay.Cleanup()
		h.relay = nil
	}
}

// startHostedSend: отправитель сам открывает порт и ждёт получателя (получатель находит его по сети
// или вводит адрес вручную). Возвращает задание отправки (его журнал показывает ход), сессию (её надо закрыть
// по окончании) и поясняющее сообщение для журнала.
func startHostedSend(s Settings, pw, text string, items []string, name string) (*Job, *HostSession, string, error) {
	port := lanRelayPorts[0]
	work, err := newWork()
	if err != nil {
		return nil, nil, "", err
	}
	ports := strings.Join(lanRelayPorts, ",")
	relay := startJob(JobSpec{Work: work, MkArgs: func(string) []string {
		return []string{"relay", "--port", port, "--ports", ports}
	}})
	if !waitTCP("127.0.0.1:"+port, 5*time.Second, relay) {
		msg := lastLine(relay.Log())
		relay.Kill()
		relay.Cleanup()
		if msg == "" {
			msg = "relay не запустился"
		}
		return nil, nil, "", fmt.Errorf("не удалось открыть порт %s (возможно, он занят другим режимом или программой): %s", port, msg)
	}
	host := &HostSession{relay: relay}
	note := ""
	if stop, err := startResponder(instanceID, roleSend, name, mustAtoi(port)); err != nil {
		note = "Поиск по сети недоступен (UDP-порт занят): получатель должен ввести адрес вручную. "
	} else {
		host.stopAnn = stop
	}

	cfg := s
	cfg.Relay, cfg.RelayPass, cfg.ProxyMode, cfg.Proxies = "127.0.0.1:"+port, "", modeDirect, nil
	job, err := startSend(cfg, pw, text, items)
	if err != nil {
		host.Close()
		return nil, nil, "", err
	}
	ips := localIPv4s()
	addr := "(адреса не найдены)"
	if len(ips) > 0 {
		addr = strings.Join(ips, ", ")
	}
	note += "Ждём получателя. Адрес этого устройства: " + addr + ". Получатель находит вас кнопкой «Найти в сети» " +
		"на вкладке «Получить» или вводит адрес вручную."
	if !skipFirewall {
		go func() {
			if err := fwEnsure(); err != nil {
				job.addNote("Не удалось открыть порты в брандмауэре: " + err.Error() + ". Если получатель не подключается, разрешите crocau.exe в брандмауэре вручную.")
			} else {
				job.addNote("Порты в брандмауэре открыты")
			}
		}()
	}
	return job, host, note, nil
}

var errBusyRole = errors.New("порты заняты режимом обмена: выключите его на вкладке «Обмен»")

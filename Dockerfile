
ARG CBOS_IMAGE_NAME
ARG CBOS_IMAGE_REPO
ARG CBOS_IMAGE_TAG

FROM ${CBOS_IMAGE_REPO}/${CBOS_IMAGE_NAME}:${CBOS_IMAGE_TAG}

COPY ./build/go-binary/eric-odp-ssh-broker /usr/bin/eric-odp-ssh-broker

ARG ERIC_ODP_SSH_BROKER_UID=141612
ARG ERIC_ODP_SSH_BROKER_GID=141612

ARG GIT_COMMIT=""

RUN echo "${ERIC_ODP_SSH_BROKER_UID}:x:${ERIC_ODP_SSH_BROKER_UID}:${ERIC_ODP_SSH_BROKER_GID}:eric-odp-ssh-broker-user:/:/bin/bash" >> /etc/passwd && \
    cat /etc/passwd && \
    sed -i "s|root:/bin/bash|root:/bin/false|g" /etc/passwd && \
    chmod -R g=u /usr/bin/eric-odp-ssh-broker && \
    chown -h ${ERIC_ODP_SSH_BROKER_UID}:0 /usr/bin/eric-odp-ssh-broker

USER $ERIC_ODP_SSH_BROKER_UID:$ERIC_ODP_SSH_BROKER_GID

CMD ["/usr/bin/eric-odp-ssh-broker"]

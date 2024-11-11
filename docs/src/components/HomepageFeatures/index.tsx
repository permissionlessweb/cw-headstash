import React from "react";

import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

import EasyDeploySvg from "@site/static/img/easy_deploy.svg";
import UniversalSupportSvg from "@site/static/img/universal_support.svg";
import FocusSvg from "@site/static/img/focus.svg";

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Easy to Use',
    Svg: EasyDeploySvg,
    description: (
      <>
        Create an interchain account (ICA) with a single instantiate call. No contracts are needed
        on the counterparty chain. Send ICA transactions as `CosmosMsg`s and receive callbacks.
      </>
    ),
  },
  {
    title: 'Fully On-Chain Deployment Workflow',
    Svg: UniversalSupportSvg,
    description: (
      <>
       The entire framework is able to be deployed via the unique IBC path the ICA makes use of. This allows for protocol level consensus for deployment and configuration of the headstash contracts.
      </>
    ),
  },
  {
    title: 'Retain Privacy While Redeeming',
    Svg: FocusSvg,
    description: (
      <>
      An optional feature we call Bloom, allows headstash claimee's to reddeem and transfer their new allocations, in such a way that retains the privacy design of Secret Networks Private Compute Enclave.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
